#include <iostream>
#include "Windows.h"

using func = void (*)();

void InstallTrampoline(func target, func source)
{
  auto memoryBasicInfo = MEMORY_BASIC_INFORMATION{};
  // Get the Base Address of the memory page containing the start of the source function
  auto const size = VirtualQuery(source, &memoryBasicInfo, sizeof(memoryBasicInfo));
  if (size == 0)
  {
    std::cout << "VirtualQuery failed!" << std::endl;
    std::exit(1);
  }

  std::cout << "BaseAddress = " << memoryBasicInfo.BaseAddress << std::endl
    << "Protect = " << memoryBasicInfo.Protect << std::endl;

  auto oldProtect = DWORD{};
  // Change the permissions on the source function's page to RWX to allow for
  // overwriting of the function's entry point
  auto const result = VirtualProtect(memoryBasicInfo.BaseAddress, memoryBasicInfo.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
  if (!result)
  {
    auto const error = GetLastError();
    std::cout << "VirtualAlloc failed to change the page access! Error code = " << error << std::endl;
    std::exit(1);
  }

  std::cout << "VirtualAlloc changed page access to PAGE_EXECUTE_READWRITE" << std::endl;

  // Overwrite the source function's entry point with a trampoline to the
  // target function. This assumes:
  // * the program has been compiled to, and is running on, an x64 processor
  // * both functions have the same calling convention
  // * both functions have the same signature
  // * there is a block of 14 bytes starting at the source function's entry
  // point, that does not overlap with the implementation of the target function

  // This is the x64 machine code for the instruction "jmp rip". The RIP
  // register contains the address of the next instruction to be executed, so
  // we append the address of the target function after this.
#define JMP_RIP "\xFF\x25\x00\x00\x00\x00"

  (void)std::memcpy(source, JMP_RIP, 6);
  auto addr = reinterpret_cast<unsigned char*>(source) + 6;
  std::memcpy(addr, &target, sizeof(target));

  std::cout << "Overwriting complete" << std::endl;
}

void AllIsWell()
{
  std::cout << "All is Well." << std::endl;
}

void SomethingWickedThisWayLies()
{
  std::cout << "Something Wicked This Way Lies!" << std::endl;
}

int main()
{
  InstallTrampoline(SomethingWickedThisWayLies, AllIsWell);
  AllIsWell();
}

// ***** Notes *****
// VV 2023-05-19: I compiled this with Visual Studio 17.4.5 (x64 only)
// Both Debug and Release successfully install the trampoline, but only Debug
// invokes it. The Release version inlines the call to AllIsWell in the main
// function, hence is invulnerable to the exploit.

