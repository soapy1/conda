import subprocess
import time


def st_time(func):
    def st_func(*args, **kwargs):
        t1 = time.time()
        r = func(*args, **kwargs)
        t2 = time.time()
        print('Function=%s, Time=%s' % (func.__name__, t2 - t1))
        return r

    return st_func


def setup_teardown_env(env_name, pre_commands=None):
    def setup_teardown(func):
        def setup_teardown_func(*args, **kwargs):
            subprocess.check_output(['conda', 'create', '-n', env_name, '-y'])
            if pre_commands:
                subprocess.check_output(pre_commands)
            func(*args, **kwargs)
            subprocess.check_output(['conda', 'env', 'remove', '-n', env_name, '-y'])
        return setup_teardown_func
    return setup_teardown


@setup_teardown_env('gofast')
@st_time
def install_simple(cmd):
    try:
        subprocess.check_output(cmd)
    except:
        print("failed")


@setup_teardown_env('metapackage-fast', ['conda', 'install', 'anaconda', 'python=3.7', '-n', 'metapackage-fast', '-y'])
@st_time
def metapackage_37(cmd):
    try:
        subprocess.check_output(cmd)
    except:
        print("failed")


@st_time
def run_conda_commands(cmd):
    try:
        subprocess.check_output(cmd)
    except:
        print("failed")


if __name__ == '__main__':
    install_test_commands = [
        ['conda', 'install', 'flask', '-n', 'gofast', '-y'],
        ['conda', 'install', 'jinja2=2.09', '-n', 'gofast', '-y'],
        ['conda', 'install', 'flask=1.1.1', 'jinja2=2.09', '-n', 'gofast', '-y'],
        ['conda', 'install', 'anaconda', '-n', 'gofast', '-y']
    ]
    for cmd in install_test_commands:
        print(cmd)
        install_simple(cmd)

    metapackage_37_commands = [
        ['conda', 'install', 'python=3.6', '-n', 'metapackage-fast', '-y'],
        ['conda', 'update', '--all', '-n', 'metapackage-fast', '-y'],
        ['conda', 'update', 'ipython'],
    ]
    # for cmd in metapackage_37_commands:
    #     print(cmd)
    #     metapackage_37(cmd)

    conda_commands = [
        ["conda", "create", "-n", "testenv", "scipy", "python=3.7", "-y"],
        ["conda", "install", "-n", "testenv", "python=3.6", "-y"],
        ["conda", "update", "-n", "testenv", "python", "-y"],
        ["conda", "env", "remove", "-n", "testenv", "-y"]
    ]
    for cmd in conda_commands:
        print(cmd)
        run_conda_commands(cmd)
