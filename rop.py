from pwn import *
from colorama import Fore, Style, init
import time

# Initialize colorama
init(autoreset=True)

user_file = input(Fore.CYAN + "Enter Your File Path: " + Style.RESET_ALL)
elf = context.binary = ELF(user_file, checksec=False)

def print_box(title, color=Fore.GREEN):
    """Print a decorative box with title"""
    width = 100
    print(color + "╔" + "═" * width + "╗")
    print(color + "║" + title.center(width) + "║")
    print(color + "╚" + "═" * width + "╝" + Style.RESET_ALL)

def display_protections():
    """Display binary protections in a colored format"""
    print("\n")
    print_box("BINARY PROTECTIONS", Fore.CYAN)
    print()
    
    # Architecture
    print(Fore.WHITE + "Architecture:  " + Fore.YELLOW + f"{elf.arch}" + Style.RESET_ALL)
    
    # RELRO
    relro_status = "Full RELRO" if elf.relro == "Full" else "Partial RELRO" if elf.relro == "Partial" else "No RELRO"
    relro_color = Fore.GREEN if elf.relro == "Full" else Fore.YELLOW if elf.relro == "Partial" else Fore.RED
    print(Fore.WHITE + "RELRO:         " + relro_color + relro_status + Style.RESET_ALL)
    
    # Stack Canary
    canary_status = "Enabled" if elf.canary else "Disabled"
    canary_color = Fore.GREEN if elf.canary else Fore.RED
    print(Fore.WHITE + "Stack Canary:  " + canary_color + canary_status + Style.RESET_ALL)
    
    # NX
    nx_status = "Enabled" if elf.nx else "Disabled"
    nx_color = Fore.GREEN if elf.nx else Fore.RED
    print(Fore.WHITE + "NX:            " + nx_color + nx_status + Style.RESET_ALL)
    
    # PIE
    pie_status = "Enabled" if elf.pie else "Disabled"
    pie_color = Fore.GREEN if elf.pie else Fore.RED
    print(Fore.WHITE + "PIE:           " + pie_color + pie_status + Style.RESET_ALL)
    
    # Stripped
    stripped_status = "Yes" if elf.stripped else "No"
    stripped_color = Fore.YELLOW if elf.stripped else Fore.GREEN
    print(Fore.WHITE + "Stripped:      " + stripped_color + stripped_status + Style.RESET_ALL)
    print()

def ask_ai(gadgets_dict):
    from openai import OpenAI
    client = OpenAI()
    
    gadgets_table = "\n".join([f"{addr}: {instr}" for addr, instr in gadgets_dict.items()])
    
    # Prepare protection details
    relro_status = "Full RELRO" if elf.relro == "Full" else "Partial RELRO" if elf.relro == "Partial" else "No RELRO"
    
    print("\n")
    print_box("SENDING DATA TO LLM", Fore.YELLOW)
    print(Fore.YELLOW + "Processing your request..." + Style.RESET_ALL)
    
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a professional exploit developer specializing in ROP chain construction."},
            {"role": "user", "content": f"""
Analyze these ROP gadgets and list ALL POSSIBLE ROP CHAINS that can be constructed.

## Available Gadgets
{gadgets_table}

## Binary Information & Protections
- Architecture: {elf.arch}
- RELRO: {relro_status}
- Stack Canary: {'Enabled' if elf.canary else 'Disabled'}
- NX: {'Enabled' if elf.nx else 'Disabled'}
- PIE: {'Enabled' if elf.pie else 'Disabled'}
- Stripped: {'Yes' if elf.stripped else 'No'}

## Output Format Required
For each possible technique, provide:
1. Technique name
2. ROP chain sequence with actual addresses
3. Brief 2-3 line explanation of how to exploit it

Example format:
execve("/bin/sh") syscall:
ROP Chain: 0x4011cc (pop rax; ret) -> 0x4011c6 (pop rdi; ret) -> 0x4011c8 (pop rsi; ret) -> 0x4011ca (pop rdx; ret) -> 0x4011ce (syscall)
Exploitation: Set rax=59 (execve syscall number), rdi=address of "/bin/sh" string, rsi=0 (argv), rdx=0 (envp), then trigger syscall to spawn shell.

read() to BSS:
ROP Chain: 0x4011cc (pop rax; ret) -> 0x4011c6 (pop rdi; ret) -> 0x4011c8 (pop rsi; ret) -> 0x4011ca (pop rdx; ret) -> 0x4011ce (syscall)
Exploitation: Set rax=0 (read syscall), rdi=0 (stdin), rsi=BSS address, rdx=size to read controlled input into writable memory for second stage.

List ALL possible ROP chains including:
- execve syscall chains
- read/write syscall chains  
- open/read/write file operations
- SROP (sigreturn) chains
- ret2libc chains
- Any other exploitation chains

Consider the binary protections when suggesting techniques. For example:
- If Canary is enabled, mention techniques to bypass/leak it
- If PIE is enabled, mention ASLR bypass strategies
- If NX is enabled, focus on ROP-based techniques

DO NOT provide:
- Python code
- Full exploit scripts
- Payload byte structures
- Markdown formatting (no **, ***, ##, ---)
- Just plain text format with technique names followed by colons

Keep explanations concise (2-3 lines max) and practical.
"""}
        ]
    )
    
    print(Fore.GREEN + "Response received successfully!\n" + Style.RESET_ALL)
    print_box("AI GENERATED ROP CHAIN ANALYSIS", Fore.MAGENTA)
    print()
    
    # Color the response output and clean markdown
    response_text = response.choices[0].message.content
    
    # Remove markdown artifacts
    response_text = response_text.replace('```', '')
    response_text = response_text.replace('###', '')
    response_text = response_text.replace('##', '')
    response_text = response_text.replace('---', '')
    response_text = response_text.replace('**', '')
    response_text = response_text.replace('*', '')
    
    lines = response_text.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            print()
            continue
            
        if line.endswith(':') and not line.startswith('ROP') and not line.startswith('Exploitation'):
            # Technique names in bright cyan - only headings colored
            print(Fore.CYAN + Style.BRIGHT + line + Style.RESET_ALL)
        else:
            # Everything else in default color
            print(line)

def display_gadget(user_file):
    from ropper import RopperService
    
    # Display protections first
    display_protections()
    
    ropservice = RopperService()
    ropservice.addFile(user_file)
    ropservice.loadGadgetsFor()
    
    print_box("AVAILABLE ROP GADGETS", Fore.MAGENTA)
    print()
    
    gadgets_dict = {}
    seen = set()
    for file in ropservice.files:
        for gadget in file.gadgets:
            gadget_str = str(gadget)
            if gadget_str not in seen:
                seen.add(gadget_str)
                if "pop" in gadget_str or "call" in gadget_str or "ret" in gadget_str or "jmp" in gadget_str or "syscall" in gadget_str:
                    # Color only important gadgets
                    if "syscall" in gadget_str:
                        print(Fore.RED + Style.BRIGHT + f"{hex(gadget.address)}: {gadget}" + Style.RESET_ALL)
                    elif "pop rdi" in gadget_str or "pop rsi" in gadget_str or "pop rdx" in gadget_str or "pop rax" in gadget_str:
                        print(Fore.GREEN + f"{hex(gadget.address)}: {gadget}" + Style.RESET_ALL)
                    else:
                        print(f"{hex(gadget.address)}: {gadget}")
                    
                    gadgets_dict[hex(gadget.address)] = str(gadget)
    
    ask_ai(gadgets_dict)

display_gadget(user_file)
