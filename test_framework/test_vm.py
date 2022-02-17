import os
import tempfile
import struct
import re
from subprocess import Popen, PIPE, run
from nose.plugins.skip import Skip, SkipTest
import ubpf.assembler
import testdata
VM = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "vm", "test")
COMPILE_SCRIPT = os.path.join(os.path.dirname(os.path.realpath(__file__)),
        "./compile.sh")


def check_datafile(filename):
    """
    Given assembly source code and an expected result, run the eBPF program and
    verify that the result matches.
    """
    data = testdata.read(filename)
    if 'asm' not in data and 'raw' not in data and 'c_prog' not in data:
        raise SkipTest("no asm or raw section in datafile")
    if 'result' not in data and 'error' not in data and 'error pattern' not in data:
        raise SkipTest("no result or error section in datafile")
    if not os.path.exists(VM):
        raise SkipTest("VM not found")

    compiling = False

    if 'raw' in data:
        code = b''.join(struct.pack("=Q", x) for x in data['raw'])
    elif 'asm' in data:
        code = ubpf.assembler.assemble(data['asm'])
    else:
        compiling = True
        # C Program
        # prog = G
        c_file_path = data['c_prog']
        compile_command = f'bash {COMPILE_SCRIPT} {c_file_path}'
        run(compile_command, shell=True)
        # NOTE: Hopefully I have compiled the c program and the binary is
        path = os.path.dirname(c_file_path)
        base = os.path.basename(c_file_path)
        name = os.path.splitext(base)[0] + '.o'
        binary = os.path.join(path, name)
        # print('binary path:', binary)
        # raise SkipTest('Not compiling')

    memfile = None

    cmd = [VM]
    if 'mem' in data:
        memfile = tempfile.NamedTemporaryFile()
        memfile.write(data['mem'])
        memfile.flush()
        cmd.extend(['-m', memfile.name])

    if not compiling:
        cmd.append('-')
    else:
        # bianry path should be set
        cmd.append(binary)


    # print(cmd)
    vm = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    if not compiling:
        stdout, stderr = vm.communicate(code)
    else:
        stdout, stderr = vm.communicate()
    stdout = stdout.decode("utf-8")
    stderr = stderr.decode("utf-8")
    stderr = stderr.strip()

    if memfile:
        memfile.close()

    if 'error' in data:
        if data['error'] != stderr:
            raise AssertionError("Expected error %r, got %r" % (data['error'], stderr))
    elif 'error pattern' in data:
        if not re.search(data['error pattern'], stderr):
            raise AssertionError("Expected error matching %r, got %r" % (data['error pattern'], stderr))
    else:
        if stderr:
            raise AssertionError("Unexpected error %r" % stderr)

    if 'result' in data:
        if vm.returncode != 0:
            raise AssertionError("VM exited with status %d, stderr=%r" % (vm.returncode, stderr))
        expected = int(data['result'], 0)
        result = int(stdout, 0)
        if expected != result:
            raise AssertionError("Expected result 0x%x, got 0x%x, stderr=%r" % (expected, result, stderr))
    else:
        if vm.returncode == 0:
            raise AssertionError("Expected VM to exit with an error code")

def test_datafiles():
    # Nose test generator
    # Creates a testcase for each datafile
    for filename in testdata.list_files():
        yield check_datafile, filename
