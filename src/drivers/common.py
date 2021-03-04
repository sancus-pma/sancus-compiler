import subprocess
import tempfile
import argparse
import os
import sys
import shutil
import atexit

import logging
from logging import debug, info, warning, error

logging.basicConfig(format='%(levelname)s: %(message)s')


def get_msp_paths():
    base = call_prog('msp430-gcc', ['-print-file-name=ldscripts'],
                     get_output=True).decode('ascii')
    base = os.path.abspath(os.path.dirname(base + '/../../..'))
    info('Found MSP430 install directory: ' + base)
    libc_include = base + '/include'
    lib = base + '/lib'
    ldscripts = lib + '/ldscripts'

    gcc_base = call_prog('msp430-gcc', ['-print-file-name=include'],
                         get_output=True).decode('ascii')
    gcc_base = os.path.abspath(os.path.dirname(gcc_base))
    info('Found MSP430 GCC install directory: ' + gcc_base)
    gcc_include = gcc_base + "/include"
    return locals()


def get_common_parser():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--verbose',
                        help='Show information messages',
                        action='store_true')
    parser.add_argument('--debug',
                        help='Show debug output and keep intermediate files',
                        action='store_true')
    parser.add_argument('-o',
                        dest='out_file',
                        help='Place the output into file',
                        metavar='file')
    parser.add_argument('in_files',
                        help='Input file(s)',
                        nargs='*',
                        metavar='file')
    return parser


def set_args(a):
    global args
    args = a
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)


def rm(*files):
    for f in files:
        try:
            if os.path.isdir(f):
                shutil.rmtree(f)
            else:
                os.remove(f)
        except:
            pass


tmp_files = []


def get_tmp(suffix=''):
    tmp = tempfile.mkstemp(suffix)[1]
    tmp_files.append(tmp)
    return tmp


def get_tmp_dir():
    tmp = tempfile.mkdtemp()
    tmp_files.append(tmp)
    return tmp


@atexit.register
def cleanup():
    if tmp_files:
        if args.debug:
            debug('Keeping temporary files: ' + ', '.join(tmp_files))
        else:
            info('Cleaning up temporary files: ' + ', '.join(tmp_files))
            rm(*tmp_files)
            del tmp_files[:]


def call_prog(prog, arguments=[], get_output=False):
    cmd = [prog] + arguments
    debug(' '.join(cmd))

    try:
        if get_output:
            return subprocess.check_output(cmd)
        else:
            subprocess.check_call(cmd)
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            fatal_error('{} is not in your PATH'.format(prog))
        else:
            fatal_error('Error running {}: {}'.format(prog, e))
    except subprocess.CalledProcessError:
        fatal_error('Command failed')


def fatal_error(msg):
    W  = '\033[0m'  # white (normal)
    R  = '\033[31m' # red
    error(R + msg + W)
    sys.exit(1)


def positive_int(string):
    val = int(string)
    if val <= 0:
        raise argparse.ArgumentTypeError('must be a positive integer')
    return val
