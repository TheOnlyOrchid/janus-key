import argparse, os, shutil, subprocess, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(command, **kwargs):
    result = subprocess.run(command, **kwargs)
    if result.returncode:
        raise SystemExit(f'{command[0]} failed with exit code {result.returncode} :(')


def quote(path):
    return '"' + str(path).replace('\\', '/') + '"'


def clean_output(build, directory):
    path = directory.resolve()
    if directory.is_symlink() or path.parent != build.resolve() or not path.is_relative_to(ROOT.parent.resolve()):
        raise SystemExit(f'bad output path: {directory}')
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)


def java(build, classpath, main_class, args=(), options=(), env=None):
    run(['java', '-Djava.io.tmpdir=' + str(build / 'tmp'), *options, '-cp', classpath,
         main_class, *map(str, args)], env=env)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ghidra', default=os.environ.get('GHIDRA_INSTALL_DIR'))
    args = parser.parse_args()
    if not args.ghidra:
        parser.error('Pass --ghidra or set GHIDRA_INSTALL_DIR please')

    install = Path(args.ghidra).resolve()
    props = dict(line.split('=', 1) for line in (install / 'Ghidra/application.properties').read_text().splitlines()
                 if '=' in line and not line.startswith('#'))
    project, build = ROOT / 'JanusKey', ROOT / 'JanusKey' / 'build'
    classes = build / 'classes'
    clean_output(build, classes)
    (build / 'tmp').mkdir(exist_ok=True)

    jars = sorted((install / 'Ghidra').glob('**/lib/*.jar'))
    classpath = os.pathsep.join(map(str, jars))
    sources = sorted((project / 'src/main/java').rglob('*.java'))
    argfile = build / 'javac.args'
    argfile.write_text('\n'.join([
        '--release', props.get('application.java.compiler', '21'), '-encoding', 'UTF-8',
        '-cp', quote(classpath), '-d', quote(classes), *[quote(source) for source in sources],
    ]), encoding='utf-8')
    run(['javac', '@' + str(argfile)])

    help_source, help_output = project / 'src/main/help', build / 'help/help'
    help_output.mkdir(parents=True, exist_ok=True)
    help_config = build / 'helpconfig'
    help_config.write_text('IndexRemove ' + str(help_source / 'help') + os.sep + '\n')
    java(build, classpath, 'com.sun.java.help.search.Indexer', [
        '-c', help_config, '-db', help_output / 'JanusKey_JavaHelpSearch',
        *help_source.rglob('*.html'),
    ])

    help_jars = []
    for jar in jars:
        with zipfile.ZipFile(jar) as archive:
            if any(name.endswith('_HelpSet.hs') for name in archive.namelist()):
                help_jars.extend(['-hp', str(jar)])
    help_env = os.environ.copy()
    for key in ('APPDATA', 'LOCALAPPDATA'):
        help_env[key] = str(build / ('help-' + key.lower()))
        Path(help_env[key]).mkdir(exist_ok=True)
    java(build, classpath, 'help.GHelpBuilder', [
        '-n', 'JanusKey', '-o', help_output, *help_jars, help_source / 'help',
    ], ['-DADDITIONAL_APPLICATION_ROOT_DIRS=' + str(install / 'Ghidra')], help_env)

    shutil.copytree(help_source, classes, dirs_exist_ok=True)
    shutil.copytree(build / 'help', classes, dirs_exist_ok=True)
    lib = build / 'JanusKey.jar'
    run(['jar', '--create', '--file', str(lib), '-C', str(classes), '.'])

    dist = project / 'dist'
    dist.mkdir(exist_ok=True)
    output = dist / ('ghidra_' + props['application.version'] + '_JanusKey.zip')
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.write(lib, 'JanusKey/lib/JanusKey.jar')
        for name in ('extension.properties', 'Module.manifest'):
            content = (project / name).read_text().replace('@extversion@', props['application.version'])
            archive.writestr('JanusKey/' + name, content)
        for source in (project / 'src').rglob('*.java'):
            archive.write(source, 'JanusKey/' + str(source.relative_to(project)).replace('\\', '/'))
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        archive.writestr('JanusKey/README.md', readme.replace('../docs/', 'docs/'))
        for name in ('GHIDRA_PERFORMANCE.md', 'GHIDRA_DESIGN.md', 'GHIDRA_RESPONSIVENESS_PLAN.md'):
            archive.write(ROOT.parent / 'docs' / name, 'JanusKey/docs/' + name)
    print(output)


if __name__ == '__main__':
    main()
