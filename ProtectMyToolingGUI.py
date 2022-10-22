#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Author:
#   Mariusz Banach / mgeeky, '20-'22
#   <mb [at] binary-offensive.com>
#   https://mgeeky.tech
#

import time
import os
import sys
from turtle import title
import yaml
import random
import clipboard

from lib.utils import *
from lib.logger import Logger
from lib.packersloader import PackersLoader
from ProtectMyTooling import VERSION
from threading import Thread

import lib.optionsparser

import PySimpleGUI as sg

sg.theme("Dark")
font = ("Consolas", 8)
font2 = ("Consolas", 10)

phrases = (
    'with great power, comes great responsibility.',
    "don't detect tools, detect techniques",
    'to be used in ethical offensive assessments only!',
    'support hard-working open-source Offensive Security Tools developers :)',
    'be responsible - watermark and track your implants',
    'be responsible - collect your implants\'s IOCs'
)

packersChain = []

# https://stackoverflow.com/a/69064884


def runCommand(cmd, timeout=None, window=None):
    cwd = os.getcwd()

    try:
        p = cmd[0]
        if len(cmd) > 1:
            p = cmd[1]

        d = os.path.dirname(os.path.normpath(os.path.abspath(p)))
        if os.path.isdir(d):
            os.chdir(d)

        p = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = ''

        for line in p.stdout:
            line = line.decode(errors='replace' if (
                sys.version_info) < (3, 5) else 'ignore').rstrip()
            output += line
            print(line)

            if window:
                window.Refresh()
                window['-outputml-'].set_vscroll_position(1.0)

        retval = p.wait(timeout)

        window.set_title("Program completed.")
        print(f'''
--------------------------------------------------------------------------------------------------------
Program completed.
''')
        return (retval, output)

    finally:
        os.chdir(cwd)



#
# https://stackoverflow.com/a/67860031
#
right_click_menu_ro = ['', ['Copy', 'Select All']]
right_click_menu = ['', ['Copy', 'Paste', 'Select All', 'Cut']]

def multilineRightClick(window, event, multilineKey, readOnly = False):
    mline: sg.Multiline = window[multilineKey]

    if event == 'Select All':
        mline.Widget.selection_clear()
        mline.Widget.tag_add('sel', '1.0', 'end')

    elif event == 'Copy':
        try:
            text = mline.Widget.selection_get()
            window.TKroot.clipboard_clear()
            window.TKroot.clipboard_append(text)
        except:
            pass

    elif event == 'Paste':
        if not readOnly:
            try:
                mline.Widget.delete("sel.first", "sel.last")
            except:
                pass
            mline.Widget.insert("insert", clipboard.paste())

    elif event == 'Cut':
        if not readOnly:
            try:
                text = mline.Widget.selection_get()
                window.TKroot.clipboard_clear()
                window.TKroot.clipboard_append(text)

                mline.Widget.delete("sel.first", "sel.last")
            
            except Exception as e:
                print(e)
                pass

def run(command, width=120):
    layout = [
        [
            sg.Multiline(
                size=(width, 40),
                key='-outputml-',
                font=font,
                echo_stdout_stderr=False,
                reroute_stdout=True,
                reroute_stderr=True, 
                no_scrollbar=False, 
                horizontal_scroll=True, 
                right_click_menu=right_click_menu_ro,
                expand_x=True,
                expand_y=True,
            )
        ],
        [
            sg.Button("Close", key="-Exit-", font=font),
        ],
    ]

    window = sg.Window("Protection in progress...",
                       layout, modal=True, finalize=True, resizable=True, return_keyboard_events=True)

    window.bind("<Escape>", "-Exit-")

    print(f'PS> {" ".join(command)}\n')
    runCommand(cmd=command, window=window)

    while True:
        event, values = window.read()
        if event == "-Exit-" or event == sg.WIN_CLOSED or event == 'Escape:27':
            break

        multilineRightClick(window, event, '-outputml-', True)

    window.close()


def editConfig(config):
    layout = [
        [
            sg.Text(config, font=font),
        ],
        [
            sg.Multiline(
                size=(120, 40), 
                font=font, 
                echo_stdout_stderr=False, 
                reroute_stdout=True,
                reroute_stderr=True, 
                key='-yaml-', 
                right_click_menu=right_click_menu,
                expand_x=True,
                expand_y=True,)
        ],
        [
            sg.Button("Save", key="-Save-", font=font),
            sg.Button("Close", key="-Exit-", font=font),
        ],
    ]

    window = sg.Window("Protection in progres...", layout,
                       modal=True, finalize=True, return_keyboard_events=True, resizable=True)
    window.bind("<Escape>", "-Exit-")

    with open(config) as f:
        print(f.read())

    while True:
        event, values = window.read()
        if event == "-Exit-" or event == sg.WIN_CLOSED or event == 'Escape:27':
            break

        if event == "-Save-":
            with open(config, 'w') as f:
                f.write(values['-yaml-'])

            sg.Popup('Saved.', 'YAML saved.')

        multilineRightClick(window, event, '-yaml-', False)

    window.close()


def createWindow(packersList):
    global packersChain

    tooltip1 = 'Inject watermark to generated artifact. Syntax: where=value, e.g.: "dos-stub=Foobar".\nAvailable watermarks: dos-stub,checksum,overlay,section\nSection requires NAME,STR syntax where NAME denotes PE section name\ne.g. "section=.foo,bar" creates PE section named ".foo" with contents "bar".\nMay be repeated'
    tooltip2 = 'Specify a custom IOC value that is to be written into output IOCs csv file in column "comment"'

    params_column = [
        [
            sg.Text("Input File" + ' ' * 1, font=font,
                    tooltip='Input implant file to be obfuscated/protected'),
            sg.Input(size=(60, 1), enable_events=True, key="-infile-", font=font,
                     tooltip='Input implant file to be obfuscated/protected', expand_x=True,),
            sg.FileBrowse(font=font),
        ],
        [
            sg.Text("Output File", font=font,
                    tooltip='Output obfuscated/protected file.'),
            sg.Input(size=(60, 1), enable_events=True, key="-outfile-",
                     font=font, tooltip='Output obfuscated/protected file.', expand_x=True,),
            sg.FileSaveAs(font=font),
        ],
        [
            sg.Text("File Architecture" + ' ' * 1, font=font,
                    tooltip='Specify input file architecture, or leave "Auto" to make script auto detect it.'),
            sg.Combo(size=(10, 1), values=["Auto", "x86", "x64"], readonly=True,
                     default_value="Auto", enable_events=True, key="-arch-", font=font,),
            sg.Text("Detected file type: ", font=font),
            sg.Text("", font=font, key='-detected-', text_color='cyan'),
        ],
        [
            sg.Column([
                [
                    sg.Listbox(values=packersChain, enable_events=True, size=(
                        25, 15), pad=(5, 5), key="-packers chain-", font=font2, expand_x=True, expand_y=True,),
                ]
            ], expand_x=True, expand_y=True,),
            sg.Column([
                [sg.Text("", font=font2)],
                [sg.Text("<-- Packers chain", font=font2)],
                [sg.Text("", font=font2)],
                [sg.Button("Move Up", font=font), ],
                [sg.Button("Move Down", font=font), ],
                [sg.Button("Remove", font=font), ],
                [sg.Button("Clear", font=font), ],
            ], expand_x=True, expand_y=True,),
        ],
        [
            sg.Text("Config path" + ' ' * 3, font=font),
            sg.Input(size=(61, 1), default_text=os.path.abspath(os.path.join(os.path.dirname(
                __file__), "config/ProtectMyTooling.yaml")), enable_events=True, key="-config-", font=font, expand_x=True,),
            sg.FileBrowse(font=font),
        ],
        [
            sg.Text("Watermark" + ' ' * 5, font=font, tooltip=tooltip1),
            sg.Input(size=(70, 1), default_text="section=.foo,1234567890abcdef123456", pad=(
                5, 5), enable_events=True, key="-watermark-", font=font, tooltip=tooltip1, expand_x=True,),
        ],
        [
            sg.Text("Custom IOC" + ' ' * 4, font=font, tooltip=tooltip2),
            sg.Input(size=(70, 1), default_text="", pad=(
                5, 5), enable_events=True, key="-customioc-", font=font, tooltip=tooltip2, expand_x=True,),
        ],
        [
            sg.Text("Custom Options" + ' ' * 0, font=font,
                    tooltip='Specify your own custom ProtectMyTooling options to be added to command line.'),
            sg.Input(size=(70, 1), default_text="", pad=(5, 5), enable_events=True, key="-customopts-", font=font,
                     tooltip='Specify your own custom ProtectMyTooling options to be added to command line.', expand_x=True,),
        ],
        [
            sg.Text("File to backdoor" + ' ' * 0, font=font,
                    tooltip='You can backdoor specific EXE/DLL file by providing path to it here AND choosing BACKDOORER packer in the chain'),
            sg.Input(size=(70, 1), default_text="", pad=(5, 5), enable_events=True, key="-backdoor-", font=font,
                     tooltip='You can backdoor specific EXE/DLL file by providing path to it here AND choosing BACKDOORER packer in the chain', expand_x=True,),
        ],
        [
            sg.Checkbox('Collect IOCs', key='-Collect IOCs-', text_color='cyan', default=False,
                        tooltip="Collect IOCs and save them to .csv file side by side to <outfile>", font=font),
            sg.Checkbox('Hide Console', key='-Hide Console-', default=False,
                        tooltip="If output artifact is PE EXE, use this option to hide Console window by switching PE Subsystem from WINDOWS_GUI", font=font),
            sg.Checkbox("Don't disable AV", key='-dont-disable-av-', default=False, font=font),
            sg.Checkbox('Verbose', key='-Verbose-', default=True, font=font),
            sg.Checkbox('Debug', key='-Debug-', default=False, font=font)
        ]
    ]

    packers_column = [
        [
            sg.Text("Choose packers to work with:", font=font),
        ],
        [
            sg.Listbox(values=packersList, enable_events=True, size=(
                20, 30), pad=(5, 5), key="-packers available-", font=font, expand_x=True, expand_y=True),
        ],
        [
            sg.Button("Add to chain", font=font, expand_x=True,),
        ]
    ]

    layout = [
        [
            sg.Column(params_column, expand_x=True, expand_y=True,),
            sg.VSeparator(),
            sg.Column(packers_column, expand_x=True, expand_y=True,),
        ],
        [
            sg.HSeparator(),
        ],
        [
            sg.Text("", key='-current chain-', font=font2),
        ],
        [
            sg.Text("", font=font),
        ],
        [
            sg.Button(
                "Protect", tooltip="Runs ProtectMyTooling.py with provided arguments.", font=font),
            sg.Button(
                "Protect & Run", tooltip="Protects input payload and runs protected file without parameters.", font=font),
            sg.Button("List Packers & Details",
                      tooltip="List all packers details.", font=font),
            sg.Button("Edit Config",
                      tooltip="Edit configuration YAML contents.", font=font),
            sg.Button("Full Help", font=font),
            sg.Button("About", font=font),
        ]
    ]

    phrase = random.choice(phrases)
    window = sg.Window(f"ProtectMyTooling v{VERSION} | {phrase} ",
                       layout, return_keyboard_events=True, resizable=True, finalize=True)
    window.bind("<Escape>", "-Exit-")

    return window


def detectFileType(p, window, values):
    global packersChain

    ftype = 'unkown'

    if os.path.isfile(p):
        if isDotNetExecutable(p):
            window['-detected-'].update('.NET Assembly')
            ftype = 'dotnet'
        elif isValidPE(p):
            window['-detected-'].update('PE Executable')
            ftype = 'pe'
        elif isShellcode(p):
            window['-detected-'].update('Shellcode')
            ftype = 'shellcode'
        else:
            window['-detected-'].update('Unknown')

    if len(values['-config-']) > 0 and os.path.isfile(values['-config-']):
        try:
            with open(values['-config-']) as f:
                parsed = yaml.load(f, Loader=yaml.FullLoader)

            if ftype == 'pe':
                packersChain = [
                    [x] for x in parsed['gui_default_chain_pe'].replace(' ', '').split(',')]
            if ftype == 'dotnet':
                packersChain = [
                    [x] for x in parsed['gui_default_chain_dotnet'].replace(' ', '').split(',')]
            if ftype == 'shellcode':
                packersChain = [
                    [x] for x in parsed['gui_default_chain_shellcode'].replace(' ', '').split(',')]

            index = 0
            window["-packers chain-"].update(packersChain, set_to_index=[
                                             index + 1], scroll_to_index=index + 1)

            chain = f'"{os.path.basename(values["-infile-"])}"'
            for p in packersChain:
                chain = f"{p[0].capitalize()}({chain})"
            window['-current chain-'].update(chain)

        except:
            pass


def main():
    global packersChain
    packersList = []

    files = os.listdir(os.path.join(os.path.dirname('__file__'), 'packers'))

    for f in files:
        if f.lower().endswith('.py'):
            name = os.path.basename(f).replace('.py', '')

            if name.lower() not in ['__init__', 'ipacker']:
                if name in RenamePackerNameToPackerFile.values():
                    name = list(RenamePackerNameToPackerFile.keys())[list(RenamePackerNameToPackerFile.values()).index(name)]
                    
                packersList.append(name)

    window = createWindow(packersList)

    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break

        elif event == "Add to chain":
            packersChain.append(values['-packers available-'])
            chain = f'"{os.path.basename(values["-infile-"])}"'
            for p in packersChain:
                chain = f"{p[0].capitalize()}({chain})"

            window['-current chain-'].update(chain)
            window["-packers chain-"].update(packersChain)

            chain = f'"{os.path.basename(values["-infile-"])}"'
            for p in packersChain:
                chain = f"{p[0].capitalize()}({chain})"

            window['-current chain-'].update(chain)

        elif event == "Remove":
            index = int(
                ''.join(map(str, window["-packers chain-"].get_indexes())))
            packersChain.pop(index)

            chain = f'"{os.path.basename(values["-infile-"])}"'
            for p in packersChain:
                chain = f"{p[0].capitalize()}({chain})"

            window['-current chain-'].update(chain)
            window["-packers chain-"].update(packersChain, set_to_index=[
                                             index - 1], scroll_to_index=index - 1)

        elif event == "Clear":
            packersChain.clear()
            window['-current chain-'].update("")
            window["-packers chain-"].update(packersChain)

        elif event == "List Packers & Details":
            script = os.path.abspath(os.path.join(
                os.path.dirname(__file__), 'ProtectMyTooling.py'))

            with tempfile.NamedTemporaryFile() as temp:
                logpath = temp.name + ".log"
                command = [
                    sys.executable,
                    script,
                    '-L',
                    '--widest-packers-list'
                ]

                run(command, width=150)

        elif event == "Move Up":
            index = int(
                ''.join(map(str, window["-packers chain-"].get_indexes())))

            if index > 0:
                packersChain.insert(index - 1, packersChain.pop(index))
                window["-packers chain-"].update(packersChain, set_to_index=[
                                                 index - 1], scroll_to_index=index - 1)

                chain = f'"{os.path.basename(values["-infile-"])}"'
                for p in packersChain:
                    chain = f"{p[0].capitalize()}({chain})"
                window['-current chain-'].update(chain)

        elif event == "Move Down":
            index = int(
                ''.join(map(str, window["-packers chain-"].get_indexes())))

            if index + 1 < len(packersChain):
                packersChain.insert(index + 1, packersChain.pop(index))
                window["-packers chain-"].update(packersChain, set_to_index=[
                                                 index + 1], scroll_to_index=index + 1)

                chain = f'"{os.path.basename(values["-infile-"])}"'
                for p in packersChain:
                    chain = f"{p[0].capitalize()}({chain})"
                window['-current chain-'].update(chain)

        elif event == "About":
            sg.Popup("About ProtectMyTooling", f'''

Mariusz Banach / mgeeky, '20-'22
<mb [at] binary-offensive.com>
(https://mgeeky.tech) 

------------------------------------------------------------
This and other projects are outcome of sleepless nights and 
plenty of hard work. If you like what I do and appreciate 
that I always give back to the community, Consider buying 
me a coffee (or better a beer) just to say thank you! :-)

https://github.com/sponsors/mgeeky

------------------------------------------------------------

Use only for legitimate, ethical engagements.

Enjoy!
''', font=font)

        elif event == "-infile-":
            p = os.path.normpath(os.path.abspath(values["-infile-"]))
            path, ext = os.path.splitext(p)
            newname = os.path.basename(path) + '-obf' + ext
            window["-infile-"].update(p)

            if len(values["-outfile-"]) == 0:
                outpath = os.path.normpath(os.path.abspath(
                    os.path.join(os.path.dirname(p), newname)))
                window["-outfile-"].update(outpath)

            #thread = Thread(target = detectFileType, args = (p, window, values))
            # thread.start()
            detectFileType(p, window, values)

        elif event == "Edit Config":
            if len(values["-config-"]) > 0:
                editConfig(values["-config-"])

        elif 'Up' in event or '16777235' in event:
            element = window.find_element_with_focus().Key

            if element in ['-packers chain-', '-packers available-']:
                cur_index = window.Element(element).Widget.curselection()
                cur_index = (
                    cur_index[0] - 1) % window.Element(element).Widget.size()
                window.Element(element).Update(set_to_index=cur_index)
                window.Element(element).Update(scroll_to_index=cur_index)
                window.write_event_value(
                    element, [window.Element(element).GetListValues()[cur_index]])

        elif 'Down' in event or '16777237' in event:
            element = window.find_element_with_focus().Key

            if element in ['-packers chain-', '-packers available-']:
                cur_index = window.Element(element).Widget.curselection()
                cur_index = (
                    cur_index[0] + 1) % window.Element(element).Widget.size()
                window.Element(element).Update(set_to_index=cur_index)
                window.Element(element).Update(scroll_to_index=cur_index)
                window.write_event_value(
                    element, [window.Element(element).GetListValues()[cur_index]])

        elif event == "Full Help":
            script = os.path.abspath(os.path.join(
                os.path.dirname(__file__), 'ProtectMyTooling.py'))
            command = [
                sys.executable,
                script,
                '-h',
                '-v',
                '-C',
            ]
            run(command)

        elif event == "Protect" or event == "Protect & Run":
            infile = os.path.normpath(os.path.abspath(values["-infile-"]))
            arch = values["-arch-"]
            watermark = values["-watermark-"]
            config = values["-config-"]
            customioc = values["-customioc-"]
            outfile = os.path.normpath(os.path.abspath(values["-outfile-"]))
            packers = ','.join([x[0] for x in packersChain])

            with tempfile.NamedTemporaryFile() as temp:
                logpath = temp.name + ".log"

                script = os.path.abspath(os.path.join(
                    os.path.dirname(__file__), 'ProtectMyTooling.py'))

                command = [
                    sys.executable,
                    script,
                    '-c',
                    config,
                    packers,
                    '-l',
                    logpath,
                    '-C',
                    infile,
                    outfile
                ]

                if arch.lower() != 'auto':
                    command.extend(['--arch', arch, ])
                if len(watermark) > 0:
                    command.extend(['-w', watermark])
                if len(customioc) > 0:
                    command.extend(['-I', customioc])

                if values['-Collect IOCs-']:
                    command.append('-i')
                if values['-Hide Console-']:
                    command.append('-g')
                if values['-Verbose-']:
                    command.append('-v')
                if values['-Debug-']:
                    command.append('-d')
                if values['-dont-disable-av-']:
                    command.extend([
                        '--check-av-command',
                        'false'
                    ])

                if len(values["-backdoor-"]) > 0:
                    backdoor = values["-backdoor-"]
                    fname, ext = os.path.splitext(backdoor.lower())

                    if ext not in ('.exe', '.dll', '.cpl', '.xll', '.wll', '.ocx', '.sys'):
                        sg.Popup("File to be backdoored must be a valid PE executable: EXE/DLL/CPL/XLL/WLL/OCX/SYS and input file must be shellcode.")
                        continue

                    command.append(f'-B')
                    command.append(f'"{backdoor.strip()}"')

                    if 'backdoor' not in [x[0].lower() for x in window["-packers chain-"].get_list_values()]:
                        sg.Popup("You did not select \"backdoor\" packer in your packers chain!")
                        continue

                if len(values["-customopts-"]) > 0:
                    opts = values["-customopts-"]
                    pos = 0
                    failed = False

                    while pos < len(opts):
                        if opts[pos] == '"':
                            pos2 = opts.find('"', pos + 1)
                            if pos2 == 0:
                                sg.Popup("Missing \" (quote) character in custom options!")
                                failed = True
                                break

                            c = opts[pos + 1:pos2]
                            command.append(c.strip())
                            pos = pos2 + 1
                        else:
                            pos2 = opts.find(' ', pos + 1)
                            if pos2 > 0:
                                c = opts[pos:pos2]
                                command.append(c.strip())
                                pos = pos2 + 1
                            else:
                                c = opts[pos:]
                                command.append(c.strip())
                                break

                    if failed:
                        continue

                if event == "Protect & Run":
                    command.append('-r')

                if os.path.isfile(outfile):
                    os.remove(outfile)

                run(command)

    window.close()


if __name__ == '__main__':
    main()
