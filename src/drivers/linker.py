#!/usr/bin/env python3

import re
import string
from collections import defaultdict

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

import sancus.config
import sancus.paths

from common import *

MAC_SIZE = int(sancus.config.SECURITY / 8)
KEY_SIZE = MAC_SIZE


class SmEntry:
    def __init__(self, name, file_name):
        self.name = name
        self.file_name = file_name


class SmRel:
    def __init__(self, sm, offset, sym):
        self.sm = sm
        self.rela_offset = offset
        self.sym = sym.strip('_')

    def get_sym(self):
        return '__sm_{0}_{1}'.format(self.sm, self.sym)

    def get_sect(self):
        return '.sm.{0}.text'.format(self.sm)

    def get_rela_sect(self):
        return '.rela.sm.{0}.text'.format(self.sm)


def rename_syms_sects(file, sym_map, sect_map):
    args = []
    for old, new in sym_map.items():
        args += ['--redefine-sym', '{}={}'.format(old, new)]
    for old, new in sect_map.items():
        args += ['--rename-section', '{}={}'.format(old, new)]

    out_file = get_tmp('.o')
    args += [file, out_file]
    call_prog('msp430-elf-objcopy', args)
    return out_file


# The `--add-symbol` option is only available for GNU binutils > msp430-gcc.
# This function therefore relies on msp430-elf-objcopy from the TI GCC port.
def add_sym(file, sym_map):
    args = []
    for sym, sect in sym_map.items():
        args += ['--add-symbol', '{0}={1}:0,weak'.format(sym, sect)]

    args += [file, file]
    call_prog('msp430-elf-objcopy', args)
    return file


def parse_size(val):
    try:
        return int(val)
    except ValueError:
        match = re.match(r'(\d+)K', val)
        if not match:
            raise ValueError('Not a valid size expression: ' + val)
        return int(match.group(1)) * 1024


def iter_symbols(elf_file):
    from elftools.elf.elffile import SymbolTableSection
    for section in elf_file.iter_sections():
        if isinstance(section, SymbolTableSection):
            yield from section.iter_symbols()


def get_symbol(elf_file, name):
    for symbol in iter_symbols(elf_file):
        sym_section = symbol['st_shndx']
        if symbol.name == name and sym_section != 'SHN_UNDEF':
            return symbol


def get_io_sym_map(sm_name):
    sym_map = {
        '__sm_handle_input':    '__sm_{}_handle_input'.format(sm_name),
        '__sm_num_inputs':      '__sm_{}_num_inputs'.format(sm_name),
        '__sm_num_connections': '__sm_{}_num_connections'.format(sm_name),
        '__sm_io_keys':         '__sm_{}_io_keys'.format(sm_name),
        '__sm_input_callbacks': '__sm_{}_input_callbacks'.format(sm_name),
        '__sm_output_nonce':    '__sm_{}_output_nonce'.format(sm_name),
        '__sm_send_output':     '__sm_{}_send_output'.format(sm_name),
        '__sm_set_key':         '__sm_{}_set_key'.format(sm_name),
        '__sm_X_exit':          '__sm_{}_exit'.format(sm_name),
        '__sm_X_stub_malloc':   '__sm_{}_stub_malloc'.format(sm_name),
        '__sm_X_stub_reactive_handle_output':
            '__sm_{}_stub_reactive_handle_output'.format(sm_name)
    }

    return sym_map


def get_io_sect_map(sm_name):
    map = {
        '.sm.X.text':       '.sm.{}.text'.format(sm_name),
        '.rela.sm.X.text':  '.rela.sm.{}.text'.format(sm_name),
    }

    for entry in ('__sm{}_set_key', '__sm{}_handle_input'):
        map['.sm.X.{}.table'.format(entry.format(''))] = \
            '.sm.{}.{}.table'.format(sm_name, entry.format('_' + sm_name))
        map['.rela.sm.X.{}.table'.format(entry.format(''))] = \
            '.rela.sm.{}.{}.table'.format(sm_name, entry.format('_' + sm_name))

    return map


def get_stub_path(stub_name):
    return '{}/{}'.format(sancus.paths.get_data_path(), stub_name)


def create_io_stub(sm, stub):
    debug('Adding I/O stub {}'.format(stub))

    return rename_syms_sects(get_stub_path(stub),
                             get_io_sym_map(sm), get_io_sect_map(sm))


def sort_entries(entries):
    # If the set_key entry exists, it should have index 0 and if the
    # handle_input entry exists, it should have index 1. This is accomplished by
    # mapping those entries to __ and ___ respectively since those come
    # alphabetically before any valid entry name.
    def sort_key(entry):
        if re.match(r'__sm_\w+_set_key', entry.name):
            return '__'
        if re.match(r'__sm_\w+_handle_input', entry.name):
            return '___'
        return entry.name

    entries.sort(key=sort_key)


parser = argparse.ArgumentParser(description='Sancus module linker.',
                                 parents=[get_common_parser()])
parser.add_argument('--standalone', action='store_true')
parser.add_argument('--ram-size',
                    choices=['128', '256', '512', '1K', '2K', '4K', '5K',
                             '8K', '10K', '16K', '24K', '32K'],
                    default='10K')
parser.add_argument('--rom-size',
                    choices=['1K', '2K', '4K', '8K', '12K', '16K', '24K',
                             '32K', '41K', '48K', '51K', '54K', '55K'],
                    default='48K')
parser.add_argument('-rdynamic', action='store_true')
parser.add_argument('--sm-stack-size',
                    help='Stack size for the module (in bytes)',
                    type=positive_int,
                    default=256,
                    metavar='size')
parser.add_argument('--prepare-for-sm-text-section-wrapping',
                    help='Make sure SM text sections can be wrapped after '
                         'linking using sancus-crypto --wrap-sm-text-sections',
                    action='store_true')
parser.add_argument('--print-default-libs',
                    help='Print libraries that are always linked',
                    action='store_true')
parser.add_argument('--inline-arithmetic',
                    help='Intercept and securely inline integer arithmetic '
                    'routines inserted by the compiler back-end',
                    action='store_true')

args, cli_ld_args = parser.parse_known_args()
set_args(args)

# Since we create our own linker script, remove the -mmcu argument.
cli_ld_args = [a for a in cli_ld_args if not a.startswith('-mmcu')]

if args.print_default_libs:
    lib_dir = sancus.paths.get_data_path() + '/lib'
    print(lib_dir + '/libsancus-sm-support.a')
    if args.standalone:
        print(lib_dir + '/libsancus-host-support.a')
    sys.exit(0)

# find all defined SMs
sms = set()
sms_entries = defaultdict(list)
sms_calls = {}
sms_unprotected_calls = {}
sms_inputs = {}
sms_outputs = {}
sms_with_isr = set()
sms_irq_handlers = defaultdict(list)
existing_sms = set()
mmio_sms = defaultdict(dict)
existing_macs = []
elf_relocations = defaultdict(list)

added_set_key_stub = False
added_input_stub = False
added_output_stub = False

input_files = args.in_files[:]
i = 0

while i < len(input_files):
    file_name = input_files[i]
    i += 1

    try:
        with open(file_name, 'rb') as f:
            elf_file = ELFFile(f)
            for section in elf_file.iter_sections():
                name = section.name
                match = re.match(r'.sm.(\w+).text', name)
                if match:
                    sm_name = match.group(1)
                    # if the following symbol exists, we assume the SM is
                    # created manually and we will output it "as is"
                    label = '__sm_{}_public_start'.format(sm_name)
                    if get_symbol(elf_file, label) is None:
                        sms.add(sm_name)
                    else:
                        existing_sms.add(sm_name)
                    continue

                match = re.match(r'.sm.(\w+).(\w+).table', name)
                if match:
                    sm_name, entry_name = match.groups()
                    sms_entries[sm_name].append(SmEntry(entry_name, file_name))
                    continue

                match = re.match(r'.rela.sm.(\w+).text', name)
                if match:
                    sm_name = match.group(1)

                    # Find call from this SM to others
                    sym = 'null'
                    symtab = elf_file.get_section(section['sh_link'])
                    for n in range(section.num_relocations()):
                        rel = section.get_relocation(n)
                        prev_sym = sym
                        sym = symtab.get_symbol(rel['r_info_sym'])

                        # Keep track of unprotected outcalls from this SM
                        # HACK: we know that the compiler-generated stubs first
                        # reference the unprotected function name, just before
                        # the '__unprotected_entry' symbol..
                        rel_match = re.match(r'__unprotected_entry', sym.name)
                        if rel_match:
                            if not sm_name in sms_unprotected_calls:
                                sms_unprotected_calls[sm_name] = set()
                            sms_unprotected_calls[sm_name].add(prev_sym.name)

                        # Intercept unprotected arithmetic function calls
                        # inserted by the compiler back-end; see also:
                        # llvm/lib/Target/MSP430/MSP430ISelLowering.cpp
                        # llvm/lib/codegen/TargetLoweringBase.cpp
                        # https://gcc.gnu.org/onlinedocs/gccint/Integer-library-routines.html
                        ari_match = re.match(r'__(u|)(ashl|ashr|lshr|mul|div|mod)(q|h|s|d|t)i.*', sym.name)
                        if ari_match and args.inline_arithmetic:
                            rela_offset = n * section['sh_entsize']
                            elf_relocations[file_name].append(
                                SmRel(sm_name, rela_offset, sym.name))
                        elif ari_match:
                            fatal_error("Arithmetic function call '{0}' "
                            "detected in SM '{1}'. Use the "
                            "`--inline-arithmetic` option to securely inline "
                            "integer arithmetic routines inserted by the "
                            "compiler back-end.".format( sym.name, sm_name))

                        rel_match = re.match(r'__sm_(\w+)_entry$', sym.name)
                        if not rel_match:
                            continue

                        # If the called entry point's name would end in "entry",
                        # the caller's text section would contain a stub whose
                        # name matches the above RE. Therefore, we check that
                        # the found symbol is not withing the caller's text
                        # section.
                        # I know, it's still hacky...
                        sym_sect_idx = sym['st_shndx']

                        if sym_sect_idx == 'SHN_UNDEF':
                            sym_sect_idx = 0 # The special NULL section

                        sym_sect = elf_file.get_section(sym_sect_idx)
                        caller_sect = elf_file.get_section_by_name(
                                                '.sm.{}.text'.format(sm_name))

                        if sym_sect != caller_sect:
                            if not sm_name in sms_calls:
                                sms_calls[sm_name] = set()
                            callee_name = rel_match.group(1)
                            sms_calls[sm_name].add(callee_name)
                    continue

                match = re.match(r'.sm.(\w+).mac.(\w+)', name)
                if match:
                    existing_macs.append((match.group(1), match.group(2)))
                    continue

            for symbol in iter_symbols(elf_file):
                name = symbol.name

                # Find the symbols used to identify asm MMIO SMs.
                # TODO we really need a decent configparser to encapsulate this
                # magic and query parsed properties in a cleaner way
                match = re.match(r'__sm_mmio_(\w+)_(secret_start|secret_end|caller_id)', name)
                if match:
                    sm, which = match.groups()
                    val = symbol['st_value']
                    mmio_sms[sm][which]=val
                    continue

                # Find the tag symbols used to identify inputs/outputs.
                # We also add the necessary stubs to the input files so that they
                # will be scanned for extra entry points later.
                match = re.match(r'__sm_(\w+)_(input|output)_tag_(\w+)', name)
                if match:
                    sm, which, name = match.groups()

                    if not added_set_key_stub:
                        input_files.append(create_io_stub(sm, 'sm_set_key.o'))
                        added_set_key_stub = True

                    if which == 'input':
                        dest = sms_inputs

                        if not added_input_stub:
                            input_files.append(create_io_stub(sm, 'sm_input.o'))
                            added_input_stub = True
                    else:
                        dest = sms_outputs

                        if not added_output_stub:
                            input_files.append(create_io_stub(sm,
                                                              'sm_output.o'))
                            added_output_stub = True

                    if not sm in dest:
                        dest[sm] = []

                    dest[sm].append(name)
                    continue

                match = re.match(r'__sm_(\w+)_isr', name)

                if match:
                    sms_with_isr.add(match.group(1))
                    continue

                match = re.match(r'__sm_(\w+)_handles_irq_(\d+)', name)

                if match:
                    sm, irq = match.groups()
                    sms_irq_handlers[sm].append(irq)
                    continue
    except IOError as e:
        fatal_error(str(e))
    except ELFError as e:
        debug('Not checking {} for SMs because it is not a valid '
              'ELF file ({})'.format(file_name, e))

for sm in sms_entries:
    sort_entries(sms_entries[sm])

if len(sms) > 0:
    info('Found new Sancus modules:')
    for sm in sms:
        info(' * {}:'.format(sm))

        if sm in sms_entries:
            entry_names = [entry.name for entry in sms_entries[sm]]
            info('  - Entries: {}'.format(', '.join(entry_names)))
        else:
            info('  - No entries')

        if sm in sms_calls:
            info('  - SM calls: {}'.format(', '.join(sms_calls[sm])))
        else:
            info('  - No calls to other modules')

        if sm in sms_unprotected_calls:
            info('  - Unprotected calls: {}'.format(', '.join(
                                                sms_unprotected_calls[sm])))
        else:
            info('  - No unprotected outcalls')

        if sm in sms_inputs:
            info('  - Inputs:  {}'.format(', '.join(sms_inputs[sm])))

        if sm in sms_outputs:
            info('  - Outputs:  {}'.format(', '.join(sms_outputs[sm])))

        if sm in sms_with_isr:
            info('  - Can be used as ISR ({})'
                            .format(', '.join(sms_irq_handlers[sm])))
else:
    info('No new Sancus modules found')

if len(existing_sms) > 0:
    info('Found existing Sancus modules:')
    for sm in existing_sms:
        info(' * {}'.format(sm))
else:
    info('No existing Sancus modules found')

if len(mmio_sms) > 0:
    info('Found asm MMIO Sancus modules:')
    for sm in mmio_sms:
        info(' * {}'.format(sm))

        if sm in sms_entries:
            entry_names = [entry.name for entry in sms_entries[sm]]
            info('  - Entries: {}'.format(', '.join(entry_names)))
        else:
            info('  - No entries')
        cid = mmio_sms[sm]['caller_id'] if 'caller_id' in mmio_sms[sm] else 'any'
        info('  - Config: callerID={}, private data=[{:#x}, {:#x}['.format(
                cid, mmio_sms[sm]['secret_start'], mmio_sms[sm]['secret_end']))
else:
    info('No asm Sancus modules found')


if args.inline_arithmetic:
    # create sm_mul asm stub for each unique SM multiplication symbol
    sms_relocations = defaultdict(set)
    for rels in elf_relocations.values():
        for sm_rel in rels:
            sms_relocations[sm_rel.sm].add(sm_rel.sym)

    # resolve dependencies (hack)
    for sm, syms in sms_relocations.items():
        if 'divhi3' in syms:
            sms_relocations[sm].add('udivhi3')
        elif 'modhi3' in syms:
            sms_relocations[sm].add('divhi3')
            sms_relocations[sm].add('udivhi3')
        elif 'umodhi3' in syms:
            sms_relocations[sm].add('udivhi3')

    # add asm stubs for final linking step
    for sm, syms in sms_relocations.items():
        for sym in syms:
            sym_map = {'__sm_mulhi3'  : '__sm_{}_mulhi3'.format(sm),
                       '__sm_divhi3'  : '__sm_{}_divhi3'.format(sm),
                       '__sm_udivhi3' : '__sm_{}_udivhi3'.format(sm),
                       '__sm_modhi3'  : '__sm_{}_modhi3'.format(sm),
                       '__sm_umodhi3' : '__sm_{}_umodhi3'.format(sm)
                      }
            sect_map = {'.sm.text' : '.sm.{}.text'.format(sm)}
            obj = sancus.paths.get_data_path() + '/sm_{}.o'.format(sym)
            input_files.append(rename_syms_sects(obj, sym_map, sect_map))

    for fn in elf_relocations:
        # add patched symbol names to infile
        sym_map = { sm_rel.get_sym() : sm_rel.get_sect() for
                        sm_rel in elf_relocations[fn] }
        add_sym(fn, sym_map)

        with open(fn, 'r+b') as f:
            elf_file = ELFFile(f)
            symtab = elf_file.get_section_by_name('.symtab')

            for sm_rel in elf_relocations[fn]:
                # calculate relocation offset (file has changed after add_sym)
                relasect = elf_file.get_section_by_name(sm_rel.get_rela_sect())
                offset = relasect['sh_offset'] + sm_rel.rela_offset

                # get symbol table index of added symbol
                for sym_idx in range(symtab.num_symbols()):
                    if symtab.get_symbol(sym_idx).name == sm_rel.get_sym():
                        break

                # overwrite symbol table index in targeted relocation
                # skip r_offset and patch r_info lower byte (litte endian)
                info("Patching relocation for symbol '{0}' in SM '{1}' ({2})".
                    format(sm_rel.get_sym(), sm_rel.sm, fn))
                f.seek(offset+5)
                f.write(bytes([sym_idx]))


# create output sections for the the SM to be inserted in the linker script
text_section = '''.text.sm.{0} :
  {{
    . = ALIGN(2);
    __sm_{0}_public_start = .;
    {6}
    {1}
    {2}
    {3}
    *(.sm.{0}.text)
    . = ALIGN(2);
    __sm_{0}_table = .;
    {4}
    . = ALIGN(2);
    {5}
    __sm_{0}_public_end = .;
  }}'''

mmio_text_section = '''.text.sm.{0} :
  {{
    . = ALIGN(2);
    __sm_{0}_public_start = .;
    {1}
    *(.sm.mmio.{0}.text)
    . = ALIGN(2);
    __sm_{0}_table = .;
    {2}
    . = ALIGN(2);
    __sm_{0}_public_end = .;
  }}'''

data_section = '''. = ALIGN(2);
    __sm_{0}_secret_start = .;
    *(.sm.{0}.data)
    . = ALIGN(2);
    {1}
    . += {2};
    __sm_{0}_stack_init = .;
    __sm_{0}_sp = .;
    . += 2;
    __sm_{0}_irq_sp = .;
    . += 2;
    __sm_{0}_tmp = .;
    . += 2;
    . = ALIGN(2);
    {3}
    {4}
    __sm_{0}_secret_end = .;'''

mac_section = '''.data.sm.{0}.mac.{1} :
  {{
    . = ALIGN(2);
    __sm_{0}_mac_{1} = .;
    BYTE(0x00); /* without this, this section will be empty in the binary */
    . += {2} - 1;
  }}'''

wrap_info_section = '''.data.sm.{0}.wrapinfo :
  {{
    . = ALIGN(2);
    __sm_{0}_wrap_nonce = .;
    SHORT(0x0000);
    __sm_{0}_wrap_tag = .;
    BYTE(0x00); /* without this, this section will be empty in the binary */
    . += {1} - 1;
  }}'''

existing_text_section = '''.text.sm.{0} :
  {{
    *(.sm.{0}.text)
  }}'''

existing_data_section = '''. = ALIGN(2);
  *(.sm.{0}.data)'''

existing_mac_section = '''.data.sm.{0}.mac.{1} :
  {{
    *(.sm.{0}.mac.{1})
  }}'''

if args.standalone:
    text_section += ' > REGION_TEXT'
    mmio_text_section += '> REGION_TEXT'
    mac_section += ' > REGION_TEXT'
    existing_text_section += ' > REGION_TEXT'
    existing_mac_section += ' > REGION_TEXT'
    wrap_info_section += ' > REGION_TEXT'

text_sections = []
data_sections = []
mac_sections = []
wrap_info_sections = []
symbols = []
for sm in sms:
    nentries = '__sm_{}_nentries'.format(sm)
    sym_map = {'__sm_entry'      : '__sm_{}_entry'.format(sm),
               '__sm_isr'        : '__sm_{}_isr'.format(sm),
               '__sm_isr_func'   : '__sm_{}_isr_func'.format(sm),
               '__sm_nentries'   : nentries,
               '__sm_table'      : '__sm_{}_table'.format(sm),
               '__sm_sp'         : '__sm_{}_sp'.format(sm),
               '__sm_irq_sp'     : '__sm_{}_irq_sp'.format(sm),
               '__sm_tmp'     : '__sm_{}_tmp'.format(sm),
               '__ret_entry'     : '__sm_{}_ret_entry'.format(sm),
               '__sm_exit'       : '__sm_{}_exit'.format(sm),
               '__sm_stack_init' : '__sm_{}_stack_init'.format(sm),
               '__sm_verify'     : '__sm_{}_verify'.format(sm)}
    sect_map = {'.sm.text' : '.sm.{}.text'.format(sm)}

    tables = []
    if sm in sms_entries:
        tables = ['{}(.sm.{}.{}.table)'.format(entry.file_name, sm, entry.name)
                      for entry in sms_entries[sm]]

    id_syms = []
    if sm in sms_calls:
        for callee in sms_calls[sm]:
            mac_sections.append(mac_section.format(sm, callee, MAC_SIZE))
            id_syms += ['__sm_{}_id_{} = .;'.format(sm, callee), '. += 2;']

        object = sancus.paths.get_data_path() + '/sm_verify.o'
        verify_file = rename_syms_sects(object, sym_map, sect_map)
        input_files.append(verify_file)

    entry_file = rename_syms_sects(sancus.paths.get_data_path() + '/sm_entry.o',
                                   sym_map, sect_map)
    isr_file_name = 'sm_isr.o' if sm in sms_with_isr else 'sm_isr_dummy.o'
    isr_file = rename_syms_sects(
        sancus.paths.get_data_path() + '/' + isr_file_name, sym_map, sect_map)
    exit_file = rename_syms_sects(sancus.paths.get_data_path() + '/sm_exit.o',
                                  sym_map, sect_map)
    input_files += [entry_file, isr_file, exit_file]

    extra_labels = ['__isr_{} = .;'.format(n) for n in sms_irq_handlers[sm]]

    # Some convenience variables for the inputs/outputs
    inputs  = sms_inputs[sm]  if sm in sms_inputs  else []
    outputs = sms_outputs[sm] if sm in sms_outputs else []
    ios     = inputs + outputs

    # Table of function pointers for the inputs
    input_callbacks = ''

    if len(inputs) > 0:
        input_callbacks += '__sm_{}_input_callbacks = .;\n'.format(sm)

        # The SHORT linker function does not output relocation information for
        # the added symbols. We work around this issue by generating and
        # compiling a C file that includes all the callbacks.
        contents = ''

        for input in inputs:
            # TODO This does not work (see comment above). However, if a way is
            # found to make SHORT output relocation information, this should be
            # done since it is way less hacky.
            # input_callbacks += '    SHORT({});\n'.format(input)
            contents += 'extern int {0};\n' \
                        'static __attribute__((section(".sm.{1}.callbacks")))' \
                        'int* __sm_{1}_callback_{0} = &{0};' \
                            .format(input, sm)

        c_file = get_tmp('.c')
        o_file = get_tmp('.o')

        with open(c_file, 'w') as f:
            f.write(contents)

        call_prog('msp430-gcc', ['-c', '-o', o_file, c_file])

        input_callbacks += '    {}(.sm.{}.callbacks)\n'.format(o_file, sm)
        input_callbacks += '    . = ALIGN(2);'

    # Table of connection keys
    io_keys = ''

    if len(ios) > 0:
        io_keys += '__sm_{}_io_keys = .;\n'.format(sm)
        io_keys += '    . += {};\n'.format(len(ios) * KEY_SIZE)
        io_keys += '    . = ALIGN(2);'

    # Nonce used by outputs
    outputs_nonce = ''

    if len(outputs) > 0:
        outputs_nonce += '__sm_{}_output_nonce = .;\n'.format(sm)
        outputs_nonce += '    . += 2;\n'
        outputs_nonce += '    . = ALIGN(2);'

    text_sections.append(text_section.format(sm, entry_file, isr_file,
                                             exit_file, '\n    '.join(tables),
                                             input_callbacks,
                                             '\n    '.join(extra_labels)))
    data_sections.append(data_section.format(sm, '\n    '.join(id_syms),
                                             args.sm_stack_size, io_keys,
                                             outputs_nonce))

    if sm in sms_entries:
        num_entries = len(sms_entries[sm])
        for idx, entry in enumerate(sms_entries[sm]):
            sym_name = '__sm_{}_entry_{}_idx'.format(sm, entry.name)
            symbols.append('{} = {};'.format(sym_name, idx))
    else:
        num_entries = 0

    symbols.append('{} = {};'.format(nentries, num_entries))

    # Add a symbol for the index of every input/output
    for index, io in enumerate(ios):
        symbols.append('__sm_{}_io_{}_idx = {};'.format(sm, io, index))

    # Add symbols for the number of connections/inputs
    symbols.append('__sm_{}_num_connections = {};'.format(sm, len(ios)))
    symbols.append('__sm_{}_num_inputs = {};'.format(sm, len(inputs)))

    if args.prepare_for_sm_text_section_wrapping:
        wrap_info_sections.append(wrap_info_section.format(sm, MAC_SIZE))

# TODO code duplication below should be refactored away
for sm in mmio_sms:
    nentries = '__sm_{}_nentries'.format(sm)
    sym_map = {'__sm_entry'      : '__sm_{}_entry'.format(sm),
               '__sm_exit'       : '__sm_{}_exit'.format(sm),
               '__sm_nentries'   : nentries,
               '__sm_table'      : '__sm_{}_table'.format(sm),
               '__sm_caller_id'  : '__sm_{}_caller_id'.format(sm)
              }
    sect_map = {'.sm.text' : '.sm.mmio.{}.text'.format(sm)}

    tables = []
    if sm in sms_entries:
        tables = ['{}(.sm.{}.{}.table)'.format(entry.file_name, sm, entry.name)
                      for entry in sms_entries[sm]]

    verifyCaller = 'caller_id' in mmio_sms[sm]
    entry_file = '/sm_mmio_exclusive.o' if verifyCaller else '/sm_mmio_entry.o'
    entry_file = rename_syms_sects(sancus.paths.get_data_path() + entry_file,
                                   sym_map, sect_map)
    args.in_files += entry_file
    text_sections.append(mmio_text_section.format(sm, entry_file,
                                                     '\n    '.join(tables)))

    # create symbol table with values known at link time
    m = mmio_sms[sm]
    symbols.append('__sm_{}_secret_start = {};'.format(sm, m['secret_start']))
    symbols.append('__sm_{}_secret_end = {};'.format(sm, m['secret_end']))
    if verifyCaller:
        symbols.append('__sm_{}_caller_id = {};'.format(sm, m['caller_id']))

    if sm in sms_entries:
        num_entries = len(sms_entries[sm])
        for idx, entry in enumerate(sms_entries[sm]):
            sym_name = '__sm_{}_entry_{}_idx'.format(sm, entry.name)
            symbols.append('{} = {};'.format(sym_name, idx))
    else:
        num_entries = 0

    symbols.append('{} = {};'.format(nentries, num_entries))

for sm in existing_sms:
    text_sections.append(existing_text_section.format(sm))
    data_sections.append(existing_data_section.format(sm))

for caller, callee in existing_macs:
    mac_sections.append(existing_mac_section.format(caller, callee))

text_sections = '\n  '.join(text_sections)
data_sections = '\n    '.join(data_sections)
mac_sections = '\n  '.join(mac_sections)
wrap_info_sections = '\n  '.join(wrap_info_sections)
symbols = '\n'.join(symbols)

tmp_ldscripts_path = get_tmp_dir()
template_path = sancus.paths.get_data_path()
msp_paths = get_msp_paths()

if args.standalone:
    mcu_ldscripts_path = tmp_ldscripts_path
    shutil.copy(template_path + '/periph.x', mcu_ldscripts_path)

    ram_length = parse_size(args.ram_size)
    rom_length = parse_size(args.rom_size)
    rom_origin = 0x10000 - rom_length
    with open(template_path + '/memory.x', 'r') as memscript:
        template = string.Template(memscript.read())

    contents = template.substitute(ram_length=ram_length,
                                    rom_length=rom_length,
                                    rom_origin=rom_origin)
    with open(mcu_ldscripts_path + '/memory.x', 'w') as memscript:
        memscript.write(contents)

    with open(template_path + '/msp430.x', 'r') as ldscript:
        template = string.Template(ldscript.read())
else:
    mcu_ldscripts_path = tmp_ldscripts_path
    with open(template_path + '/sancus.ld', 'r') as ldscript:
        template = string.Template(ldscript.read())

contents = template.substitute(sm_text_sections=text_sections,
                               sm_data_sections=data_sections,
                               sm_mac_sections=mac_sections,
                               sm_wrap_info_sections=wrap_info_sections,
                               sm_symbols=symbols,
                               mcu_ldscripts_path=mcu_ldscripts_path)

ldscript_name = tmp_ldscripts_path + '/msp430.x'
with open(ldscript_name, 'w') as ldscript:
    ldscript.write(contents)

#with open(ldscript_name, 'r') as ldscript:
    #print ldscript.read()

out_file = args.out_file
if not out_file:
    out_file = 'a.out'

info('Using output file ' + out_file)

ld_args = ['-L', mcu_ldscripts_path, '-L', msp_paths['lib'],
           '-L', sancus.paths.get_data_path() + '/lib',
           '-T', ldscript_name, '-o', out_file]
ld_libs = ['-lsancus-sm-support']

if args.standalone:
    ld_libs += ['-lsancus-host-support']
    ld_args += input_files + cli_ld_args + ld_libs
    call_prog('msp430-gcc', ld_args)
else:
    # Since we are calling ld directly we have to transform all the -Wl options
    for arg in cli_ld_args:
        if arg.startswith('-Wl'):
            ld_args += arg.split(',')[1:]
        else:
            ld_args.append(arg)

    # -d makes sure no COMMON symbols are created since these are annoying to
    # handle in the dynamic loader (and pretty useless anyway)
    ld_args += ['-r', '-d'] + input_files + ld_libs
    call_prog('msp430-ld', ld_args)
