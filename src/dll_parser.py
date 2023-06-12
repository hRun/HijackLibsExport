import glob
import os
import yaml


src_msft = os.path.join('HijackLibs', 'yml', 'microsoft')
src_othr = os.path.join('HijackLibs', 'yml', '3rd_party')
dst_msft = os.path.join('msft_dlls.csv')
dst_othr = os.path.join('othr_dlls.csv')

path_mapping = {
    '%SYSTEM32%': 'C:\\Windows\\System32', 
    '%SYSWOW64%': 'C:\\Windows\\SysWOW64', 
    '%WINDIR%': 'C:\\Windows', 
    '%PROGRAMDATA%': 'C:\\ProgramData',
    '%PROGRAMFILES%': 'C:\\Program Files', # might as well be Program Files (x86)?!
    '%APPDATA%': 'C:\\Users\\<User>\\AppData\\Roaming', # actual path dependent on user
    '%LOCALAPPDATA%': 'C:\\Users\\<User>\\AppData\\Local', # actual path dependent on user
    '%USERPROFILE%': 'C:\\Users\\<User>' # actual path dependent on user
}


def parse_sources(src_dir: str, dst_file: str) -> bool:
    with open(dst_file, 'w') as dst:
        dst.write('"LibraryName", "LibraryPath", "LibraryPathGeneric", "ExecutableName", "ExecutablePath", "ExecutablePathGeneric", "Type"\n')

    for filename in glob.iglob(src_dir + '**/**', recursive=True):
        if filename.endswith('.yml'):
            with open(filename, 'r') as src:
                try:
                    spec = yaml.safe_load(src)
                    
                    if not 'ExpectedLocations' in spec: # shadowloading
                        spec['ExpectedLocations'] = ''

                    for location in spec['ExpectedLocations']: # dll can exist in multiple places
                        with open(dst_file, 'a') as dst:
                            for exe in spec['VulnerableExecutables']: # multiple exes can use the same dll insecurely
                                dst.write(
                                    '"{}","{}","{}","{}","{}","{}","{}"\n'.format(
                                        spec['Name'], 
                                        os.path.join(path_mapping[location.split('\\', 1)[0]], location.split('\\', 1)[1], spec['Name']).replace('/', '\\') if len(location.split('\\', 1)) > 1 else os.path.join(path_mapping[location.split('\\', 1)[0]], spec['Name']).replace('/', '\\'), 
                                        os.path.join(location, spec['Name']).replace('/', '\\'), 
                                        exe['Path'].split('\\')[-1] if '\\' in exe['Path'] else exe['Path'], 
                                        os.path.join(path_mapping[exe['Path'].split('\\', 1)[0]], exe['Path'].split('\\', 1)[1]).replace('/', '\\') if '\\' in exe['Path'] else '', 
                                        exe['Path'] if '\\' in exe['Path'] else '', 
                                        exe['Type']
                                    )
                                )
                except Exception as e:
                    print('Something went wrong. Skipping "', filename, '". ', e)
                    pass


parse_sources(src_msft, dst_msft)
parse_sources(src_othr, dst_othr)
