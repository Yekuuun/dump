/**
 * A basic PE section dumper => displaying informations properly. 
 * Author : Yekuuun
 * Github : https://github.com/NightFall-Security
 */

#include <memory>
#include <cstring>
#include "pe.hpp"

#define MAX_SECTION_NAME_LEN 8
#define BYTES_PER_LINE 16

#define COLOR_PINK "\033[38;5;206m" //PINK.
#define COLOR_RESET "\033[0m"

using namespace std;

/**
 * base class handling PE base functions. => load & dump.
 */
class PeViewer {
    private:
        PBYTE pRawPe = nullptr;
        PBYTE pBuff  = nullptr;

        //commong build objet properties.
        CHAR* cPath;
        CHAR* cSection;

        /**
         * Displaying banner.
         */
        VOID DisplayBanner() {
            std::cout << COLOR_PINK;
            std::cout << "======================================" << std::endl;
            std::cout << "        PE Section Dumper Tool        " << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << " File: " << this->cPath << std::endl;
            std::cout << " Section: " << this->cSection << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << COLOR_RESET;
        }

        /**
         * Freeing memory allocated for PE file (raw & in mem.)
         */
        VOID Unload(){
            if (this->pBuff) {
                MEMORY_BASIC_INFORMATION mbi;
        
                if (VirtualQuery(this->pBuff, &mbi, sizeof(mbi)))
                    VirtualFree(this->pBuff, 0, MEM_RELEASE);
        
                this->pBuff = nullptr;
            }

            if(this->pRawPe){
                HeapFree(GetProcessHeap(), 0, this->pRawPe);
                this->pRawPe = nullptr;
            }
        }

        /**
         * Printing hex ascii when dumping section.
         */
        VOID PrintHexAscii(const BYTE* data, DWORD size) {
            for (DWORD i = 0; i < size; i += BYTES_PER_LINE) {
                printf("%08X  ", i);
        
                // Affichage en hexadécimal
                for (DWORD j = 0; j < BYTES_PER_LINE; j++) {
                    if (i + j < size)
                        printf("%02X ", data[i + j]);
                    else
                        printf("   ");
                }
        
                printf(" |");
        
                // Affichage en ASCII
                for (DWORD j = 0; j < BYTES_PER_LINE; j++) {
                    if (i + j < size)
                        printf("%c", isprint(data[i + j]) ? data[i + j] : '.');
                }
        
                printf("|\n");
            }
        }

        /**
         * Dumping section from PE.
         */
        VOID Dump(){
            if(this->pBuff == nullptr){
                cout << "[!] No loaded PE file." << endl;
                return;
            }

            CHAR*  cSection = this->cSection;
            SIZE_T sSection = strlen(cSection);

            PIMAGE_NT_HEADERS pNtHdr = GetNtHdr(this->pBuff);
            PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdr);

            for (WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
                BYTE* pSectionName = (BYTE*)pSection[i].Name;
                if (memcmp(pSectionName, cSection, sSection) == 0) {
                    cout << "[*] Found " << cSection << " section :" << endl;
                    printf("\t- Virtual Size: 0x%08X\n", pSection[i].Misc.VirtualSize);
                    printf("\t- Raw Size: 0x%08X\n", pSection[i].SizeOfRawData);
                    
                    cout << "\n" << endl;
                    cout << "[*] Dumping section " << this->cSection << " : \n" << endl;
                    BYTE* pStartSection = ((BYTE*)pRawPe + pSection[i].PointerToRawData);
                    this->PrintHexAscii(pStartSection, pSection[i].SizeOfRawData);

                    cout << "[*] Successfully dumped section." << endl;
                    return;
                }
            }
        }

        /**
         * Loading PE file into memory.
         */
        BOOL Load(){
            DWORD dwSize = 0;
            this->pRawPe = ReadPeFile(this->cPath, &dwSize);

            if(this->pRawPe == nullptr)
                return false;
            
            cout << "[*] Loading file into memory... " << endl;
            
            //loading it into memory.
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)this->pRawPe;
            PIMAGE_NT_HEADERS pNtHdr  = (PIMAGE_NT_HEADERS)(this->pRawPe + pDos->e_lfanew);

            if(!IsValidPeFile(this->pRawPe)){
                cout << "[!] Not a valid PE file..." << endl;
                return false;
            }

            this->pBuff = (PBYTE)VirtualAlloc(NULL, pNtHdr->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if(this->pBuff == nullptr){
                cout << "[!] Error allocating memory." << endl;
                return false;
            }

            MapSections(this->pRawPe, this->pBuff, pNtHdr);
            cout << "[*] Successfully mapped sections." << endl;
        
            if(!Relocate(this->pBuff, pNtHdr, (FIELD_PTR)this->pBuff)){
                cout << "[*] Error applying relocations." << endl;
                return false;
            }
        
            if(!LoadImports(pBuff, pNtHdr)){
                cout << "[!] Error loading imports" << endl;
                return false;
            }
        
            cout << "[*] Successfully mapped PE into memory." << endl;
            return true;
        }
    
    public:
        PeViewer(IN CHAR* path, IN CHAR* section): cPath{path}, cSection{section} {};
        ~PeViewer(){
            this->Unload();
        }

        /**
         * Load & dump informations.
         */
        BOOL LoadAndDump(){
            this->DisplayBanner();

            if(!this->Load() || this->pBuff == nullptr)
                return false;
            
            //ok loaded. => dump.
            this->Dump();
            return true;
        }
};

/**
 * Entry point.
 */
int main(int argc, char ** argv){
    if(argc != 3){
        cout << "[!] Must pass 2 params : dump.exe <path_to_file> <section_name> " << endl;
        return EXIT_FAILURE;
    }

    //args.
    CHAR* lpPath = argv[1];
    CHAR* lpName = argv[2];

    SIZE_T sSectionName = strlen(lpName);
    if(sSectionName > MAX_SECTION_NAME_LEN){
        cout << "[!] Section name incorrect. => max 8 characters" << endl;
        return EXIT_FAILURE;
    }

    //dumping section.
    auto pe = std::make_unique<PeViewer>(lpPath, lpName);
    if (!pe->LoadAndDump()) {
        cout << "[!] Failed to load and dump section." << endl;
        return EXIT_FAILURE;
    }

    cout << "[$] Ending DUMP ! CIAO... " << endl;
    return EXIT_SUCCESS;
}