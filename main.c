/*
 * Enumerador de procesos - Proyecto #3
 * Técnica: CreateToolhelp32Snapshot (Win32 API)
 *
 * El malware usa esto para reconocimiento: saber qué corre en el sistema,
 * buscar antivirus, detectar VMs/sandboxes, o encontrar procesos para inyectar.
 *
 * USO EDUCATIVO - Ejecutar solo en tu propia máquina/VM.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tlhelp32.h>  // Tool Help Library: APIs para enumerar procesos, hilos, módulos
#include <stdio.h>

// Lista de procesos que el malware busca para decidir si ejecutarse o no
// Si encuentra un antivirus, puede intentar matarlo o simplemente no ejecutar su payload
// Si encuentra herramientas de análisis (VM, sandbox), sabe que lo están investigando

typedef struct {
    const char* name;      // nombre del proceso
    const char* category;  // qué tipo de herramienta es
} TARGET_PROCESS;

TARGET_PROCESS targets[] = {
    // Antivirus
    {"MsMpEng.exe",        "Windows Defender"},
    {"avp.exe",            "Kaspersky"},
    {"avgui.exe",          "AVG"},
    {"avguard.exe",        "Avira"},
    {"bdagent.exe",        "Bitdefender"},
    {"MBAMService.exe",    "Malwarebytes (servicio)"},
    {"mbamtray.exe",       "Malwarebytes (tray)"},

    // Herramientas de análisis / sandbox
    {"wireshark.exe",      "Wireshark (sniffer)"},
    {"procmon.exe",        "Process Monitor (Sysinternals)"},
    {"procexp.exe",        "Process Explorer (Sysinternals)"},
    {"x64dbg.exe",         "x64dbg (debugger)"},
    {"ollydbg.exe",        "OllyDbg (debugger)"},
    {"ida.exe",            "IDA Pro (disassembler)"},
    {"pestudio.exe",       "PEStudio (analyzer)"},

    // VM / Sandbox
    {"vmtoolsd.exe",       "VMware Tools"},
    {"vmwaretray.exe",     "VMware Tray"},
    {"VBoxService.exe",    "VirtualBox Guest"},
    {"VBoxTray.exe",       "VirtualBox Tray"},
    {"sandboxiedcomlaunch.exe", "Sandboxie"},
};

// sizeof(targets) = tamaño total del array en bytes
// sizeof(targets[0]) = tamaño de UN elemento
// dividir = número de elementos
#define TARGET_COUNT (sizeof(targets) / sizeof(targets[0]))

// Compara dos strings ignorando mayúsculas/minúsculas
// _stricmp: "i" = case Insensitive. Retorna 0 si son iguales
// Necesario porque "svchost.exe" y "SvcHost.exe" son el mismo proceso
int match_target(const char* exe_name) {
    for (int i = 0; i < TARGET_COUNT; i++) {
        if (_stricmp(exe_name, targets[i].name) == 0) {
            return i;  // retorna el índice del target encontrado
        }
    }
    return -1;  // no encontrado
}

// DLLs sospechosas que indican análisis, hooking o sandbox
// El malware revisa qué DLLs tiene cargadas un proceso para saber si lo están monitoreando
const char* suspicious_dlls[] = {
    "sbiedll.dll",      // Sandboxie: inyecta esta DLL en todos los procesos sandboxeados
    "dbghelp.dll",      // Cargada cuando un debugger está attached
    "api_log.dll",      // Usada por algunas sandboxes para interceptar API calls
    "snxhk.dll",        // Avast/Norton: hook DLL para monitorear comportamiento
    "cmdvrt32.dll",     // Comodo sandbox: DLL de virtualización
    "pstorec.dll",      // A veces presente en entornos de análisis
};

#define SUSPICIOUS_DLL_COUNT (sizeof(suspicious_dlls) / sizeof(suspicious_dlls[0]))

// Enumera los módulos (DLLs) cargados en un proceso dado su PID
// TH32CS_SNAPMODULE: snapshot de los módulos de UN proceso específico
// Requiere permisos: no funciona con procesos protegidos (System, csrss, etc.)
void enumerate_modules(DWORD pid, const char* process_name) {
    // TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32:
    // El OR combina flags para capturar módulos de 64-bit Y 32-bit
    // Sin SNAPMODULE32, un proceso WOW64 (32-bit en Windows 64) no mostraría sus DLLs
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

    if (snap == INVALID_HANDLE_VALUE) {
        // ERROR_ACCESS_DENIED (5) = proceso protegido, no podemos leer sus módulos
        // Esto es normal para procesos del sistema como csrss.exe, System, etc.
        printf("    (no se pudo acceder a los modulos - Error: %lu)\n", GetLastError());
        return;
    }

    // MODULEENTRY32W: info de cada módulo (DLL) cargado
    // Incluye: nombre, dirección base en memoria, tamaño, path completo
    MODULEENTRY32W me;
    me.dwSize = sizeof(MODULEENTRY32W);  // mismo patrón que PROCESSENTRY32W

    if (!Module32FirstW(snap, &me)) {
        CloseHandle(snap);
        return;
    }

    int mod_count = 0;
    int suspicious_count = 0;

    printf("\n  Modulos de %s (PID %lu):\n", process_name, pid);
    printf("  %-30s %-18s %s\n", "MODULO", "DIR. BASE", "TAMAÑO");
    printf("  %-30s %-18s %s\n", "------------------------------", "------------------", "--------");

    do {
        char mod_name[260];
        wcstombs(mod_name, me.szModule, sizeof(mod_name));

        // me.modBaseAddr = dirección donde Windows cargó esta DLL en memoria
        // En malware: necesitas esta dirección para calcular offsets de funciones
        // me.modBaseSize = cuántos bytes ocupa el módulo en memoria
        printf("  %-30s 0x%p  %lu KB\n",
            mod_name,
            (void*)me.modBaseAddr,
            me.modBaseSize / 1024);

        // Revisar si esta DLL es sospechosa
        for (int i = 0; i < SUSPICIOUS_DLL_COUNT; i++) {
            if (_stricmp(mod_name, suspicious_dlls[i]) == 0) {
                printf("  >>> [SOSPECHOSA] %s detectada!\n", mod_name);
                suspicious_count++;
            }
        }

        mod_count++;
    } while (Module32NextW(snap, &me));

    printf("  [+] %d modulos cargados", mod_count);
    if (suspicious_count > 0) {
        printf(", %d SOSPECHOSOS", suspicious_count);
    }
    printf("\n");

    CloseHandle(snap);
}

int main(void) {

    printf("[*] Enumerador de procesos iniciado\n\n");

    // CreateToolhelp32Snapshot: toma una "foto" de todos los procesos del sistema
    // TH32CS_SNAPPROCESS = queremos snapshot de procesos (también existe para hilos, módulos, etc.)
    // 0 = no filtrar por PID, queremos TODOS los procesos
    // Retorna un HANDLE: un identificador para acceder al snapshot después
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // INVALID_HANDLE_VALUE = falló (permisos insuficientes, etc.)
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Error: no se pudo crear el snapshot (codigo: %lu)\n", GetLastError());
        return 1;
    }

    printf("[+] Snapshot creado exitosamente\n\n");

    // Encabezado de tabla
    // %-8s = alinear a la izquierda, 8 caracteres de ancho
    // %-10s = 10 caracteres de ancho
    // Esto crea columnas parejas como en un Task Manager
    printf("%-8s %-8s %-6s %s\n", "PID", "PPID", "HILOS", "PROCESO");
    printf("%-8s %-8s %-6s %s\n", "-------", "-------", "-----", "-----------------------------");

    // PROCESSENTRY32W: estructura que Windows llena con info de cada proceso
    // La W = Wide (Unicode, wchar_t). Visual Studio usa Unicode por defecto
    // Si usáramos PROCESSENTRY32 (sin W), los nombres salen con un solo carácter
    // porque printf("%s") lee chars de 1 byte pero Unicode usa 2 bytes por carácter
    PROCESSENTRY32W pe;

    // OBLIGATORIO: inicializar dwSize con el tamaño de la estructura
    // Si no lo haces, Process32First falla silenciosamente
    // Windows usa dwSize para saber qué versión de la estructura estás usando
    pe.dwSize = sizeof(PROCESSENTRY32W);

    // Process32FirstW: versión Unicode de Process32First
    if (!Process32FirstW(snapshot, &pe)) {
        printf("[!] Error: no se pudo leer el primer proceso\n");
        CloseHandle(snapshot);
        return 1;
    }

    // Process32Next: avanza al SIGUIENTE proceso del snapshot
    // Retorna FALSE cuando no hay más procesos (fin de la lista)
    // Es como un iterador: First() inicializa, Next() avanza
    int count = 0;
    do {
        // Convertir nombre de wchar_t (Unicode) a char (ANSI) para usar solo printf
        // wcstombs = Wide Character String To Multi-Byte String
        // Mezclar printf y wprintf causa problemas de buffer — mejor convertir
        char exe_name[260];
        wcstombs(exe_name, pe.szExeFile, sizeof(exe_name));

        // pe.th32ProcessID       = PID del proceso (identificador único)
        // pe.th32ParentProcessID = PPID: PID del proceso que lo creó (padre)
        // pe.cntThreads          = número de hilos del proceso
        //
        // PPID es clave en malware analysis: si notepad.exe fue creado por
        // cmd.exe (PPID apunta a cmd), es normal. Si fue creado por
        // un .exe random, es sospechoso (posible inyección).
        printf("%-8lu %-8lu %-6lu %s\n",
            pe.th32ProcessID,
            pe.th32ParentProcessID,
            pe.cntThreads,
            exe_name);
        count++;
    } while (Process32NextW(snapshot, &pe));

    printf("\n[+] Total: %d procesos encontrados\n", count);

    // Segunda pasada: buscar procesos de interés
    // Tomamos un nuevo snapshot porque ya consumimos el anterior con Process32Next
    printf("\n========================================\n");
    printf("  DETECCION DE PROCESOS DE INTERES\n");
    printf("========================================\n\n");

    HANDLE snapshot2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot2 != INVALID_HANDLE_VALUE) {
        pe.dwSize = sizeof(PROCESSENTRY32W);

        int detections = 0;

        if (Process32FirstW(snapshot2, &pe)) {
            do {
                char exe_name[260];
                wcstombs(exe_name, pe.szExeFile, sizeof(exe_name));

                int idx = match_target(exe_name);
                if (idx >= 0) {
                    printf("  [!] %-25s -> %s (PID: %lu)\n",
                        exe_name,
                        targets[idx].category,
                        pe.th32ProcessID);

                    // Enumerar las DLLs del proceso detectado
                    // Esto muestra qué tiene cargado ese AV/herramienta
                    enumerate_modules(pe.th32ProcessID, exe_name);
                    printf("\n");

                    detections++;
                }
            } while (Process32NextW(snapshot2, &pe));
        }

        if (detections == 0) {
            printf("  Ningun proceso de interes detectado.\n");
        } else {
            printf("\n  [+] %d procesos de interes encontrados\n", detections);
        }

        CloseHandle(snapshot2);
    }

    CloseHandle(snapshot);

    return 0;
}
