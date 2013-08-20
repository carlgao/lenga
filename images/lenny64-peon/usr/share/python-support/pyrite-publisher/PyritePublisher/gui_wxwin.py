#
#  $Id: gui_wxwin.py,v 1.2 2002/03/28 04:55:14 rob Exp $
#
#  Copyright 2001 Rob Tillotson <rob@pyrite.org>
#  All Rights Reserved
#
#  Permission to use, copy, modify, and distribute this software and
#  its documentation for any purpose and without fee or royalty is
#  hereby granted, provided that the above copyright notice appear in
#  all copies and that both the copyright notice and this permission
#  notice appear in supporting documentation or portions thereof,
#  including modifications, that you you make.
#
#  THE AUTHOR ROB TILLOTSON DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
#  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
#  RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
#  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
#  CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE!
#
"""
"""

__version__ = '$Id: gui_wxwin.py,v 1.2 2002/03/28 04:55:14 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import os

# NOTE -- the following line is X specific.  I don't care.
# wxPython has a bug in which it will invoke the C exit() function
# if there isn't a display available.

if not os.environ.has_key("DISPLAY"):
    raise ImportError, 'No display set; cannot import wxPython'

from wxPython.wx import *

import sys

import dtkmain
        
class PPPluginBrowser(wxDialog):
    ID_LISTBOX = 201
    ID_PROPERTY_GRID = 202
    
    def __init__(self, parent, instance=None):
        wxDialog.__init__(self, parent, -1, "Plugins", wxDefaultPosition,
                          wxSize(500,300))#, wxSYSTEM_MENU|wxCAPTION)
        self.instance = instance

        # layout:
        #   vertical box sizer
        #     horizontal sizer
        #       listbox control
        #       notebook sizer
        #         notebook
        #           info panel
        #             various static text boxes
        #           property panel
        #             dropdown box
        #             edit field
        #     horizontal sizer
        #       close button
        #

        top_sizer = wxBoxSizer(wxVERTICAL)

        main_sizer = wxBoxSizer(wxHORIZONTAL)
        # main window

        self.listbox = wxListBox(self, self.ID_LISTBOX)
        main_sizer.Add(self.listbox, 1, wxEXPAND|wxRIGHT, 5)

        pnames = self.instance.plugins.keys()
        pnames.sort()
        plugin = self.instance.plugins[pnames[0]]
        self.listbox.InsertItems(pnames,0)
        EVT_LISTBOX(self, self.ID_LISTBOX, self.listbox_select)
        
        notebook = wxNotebook(self, -1)
        
        # notebook info page
        info_panel = wxPanel(notebook, -1)
        notebook.AddPage(info_panel, "Info")
        sz0 = wxBoxSizer(wxHORIZONTAL)
        sz = wxFlexGridSizer(0,2,2,2)
        sz.Add(wxStaticText(info_panel, -1, "Name:"))
        self.l_name = wxStaticText(info_panel, -1, plugin.name)
        sz.Add(self.l_name)
        
        sz.Add(wxStaticText(info_panel, -1, "Version:"))
        self.l_version=wxStaticText(info_panel, -1, plugin.version)
        sz.Add(self.l_version)
        
        sz.Add(wxStaticText(info_panel, -1, "Author:"))
        self.l_author = wxStaticText(info_panel, -1, "%s <%s>" % (plugin.author, plugin.author_email))
        sz.Add(self.l_author)
        
        sz.Add(wxStaticText(info_panel, -1, "Description:"))
        #self.l_description = wxTextCtrl(self.info_panel, -1, "Plugin Description",
        #                                style = wxTE_READONLY|wxTE_MULTILINE)
        self.l_description = wxStaticText(info_panel, -1, plugin.description)
        sz.Add(self.l_description)
        sz0.Add(sz, 1, wxEXPAND|wxALL, 5)

        info_panel.SetAutoLayout(true)
        info_panel.SetSizer(sz0)

        main_sizer.Add(notebook, 2, wxEXPAND)

        top_sizer.Add(main_sizer, 1, wxEXPAND|wxALL, 5)

        # button box
        button_sizer = wxBoxSizer(wxHORIZONTAL)
        button_sizer.Add(wxButton(self, wxID_CANCEL, "Close"), 0, wxALIGN_RIGHT)
            
        top_sizer.Add(button_sizer, 0, wxALIGN_RIGHT|wxALL, 5)

        self.SetAutoLayout(true)
        self.SetSizer(top_sizer)
        top_sizer.SetMinSize(wxSize(500,300))
        top_sizer.Fit(self)
        
    def listbox_select(self, event):
        p = self.listbox.GetStringSelection()
        plugin = self.instance.plugins[p]

        self.l_name.SetLabel(plugin.name)
        self.l_version.SetLabel(plugin.version)
        self.l_author.SetLabel("%s <%s>" % (plugin.author, plugin.author_email))
        self.l_description.SetLabel(plugin.description)
        
        
class PPMainFrame(wxFrame):
    ID_INFILENAME = 201
    ID_INFILEBUTTON = 202
    ID_GOBUTTON = 203
    ID_OUTFILEBUTTON = 204
    ID_OUTFILENAME = 205
    ID_PICK_TASK = 206
    
    M_ID_ABOUT = 101
    M_ID_EXIT = 102
    M_ID_PLUGINS = 103

    def __init__(self, parent, ID, title, instance=None):
        wxFrame.__init__(self, parent, ID, title, wxDefaultPosition,
                         wxSize(500,300))

        self.instance = instance
        
        self.CreateStatusBar()

        help_menu = wxMenu()
        help_menu.Append(self.M_ID_ABOUT, "&About",
                    "More information about Pyrite Publisher")
        EVT_MENU(self, self.M_ID_ABOUT, self.menu_about)

        file_menu = wxMenu()
        file_menu.Append(self.M_ID_PLUGINS, "&Plugins...",
                         "Plugin information and properties")
        EVT_MENU(self, self.M_ID_PLUGINS, self.menu_plugins)
        file_menu.AppendSeparator()
        file_menu.Append(self.M_ID_EXIT, "E&xit",
                         "Exit Pyrite Publisher")
        EVT_MENU(self, self.M_ID_EXIT, self.menu_exit)

        menuBar = wxMenuBar()
        menuBar.Append(file_menu, "&File")
        menuBar.Append(help_menu, "&Help")

        self.SetMenuBar(menuBar)

        mainsizer = wxBoxSizer(wxVERTICAL)

        sz = wxFlexGridSizer(0,3,5,5)
        sz.AddGrowableCol(1) # where is this documented???
        
        sz.Add(wxStaticText(self, -1, "Input File:"), 0, wxALL|wxALIGN_RIGHT, 5)
        self.ctrl_infile = wxTextCtrl(self, self.ID_INFILENAME)
        sz.Add(self.ctrl_infile, 1, wxEXPAND)
        sz.Add(wxButton(self, self.ID_INFILEBUTTON, "Choose...", wxDefaultPosition),0)
        EVT_BUTTON(self, self.ID_INFILEBUTTON, self.button_chooseinput)

        sz.Add(wxStaticText(self, -1, "Output File:"), 0, wxALL|wxALIGN_RIGHT, 5)
        self.ctrl_outfile = wxTextCtrl(self, self.ID_OUTFILENAME)
        sz.Add(self.ctrl_outfile, 1, wxEXPAND)
        sz.Add(wxButton(self, self.ID_OUTFILEBUTTON, "Choose...", wxDefaultPosition),0)
        EVT_BUTTON(self, self.ID_OUTFILEBUTTON, self.button_chooseoutput)

        # task combobox
        sz.Add(wxStaticText(self, -1, "Task:"), 0, wxALL|wxALIGN_RIGHT, 5)
        self.tasks = self.instance.tasks.items()
        self.tasks.sort()
        self.pick_task = wxChoice(self, self.ID_PICK_TASK, wxDefaultPosition,
                                  wxDefaultSize, ["Automatic conversion"]+\
                                  [t.title for k,t in self.tasks])
        self.pick_task.SetSelection(0)
        sz.Add(self.pick_task, 1, wxEXPAND)
        sz.Add(wxStaticText(self, -1, ""), 0, wxALL|wxALIGN_RIGHT, 5)
        
        mainsizer.Add(sz, 0, wxEXPAND|wxALL, 5)

        
        sz0 = self.init_advanced_options()
        mainsizer.Add(sz0,2,wxALL|wxEXPAND,5)
        
        # button box
        sz = wxBoxSizer(wxHORIZONTAL)
        sz.Add(wxButton(self, self.ID_GOBUTTON, "Convert"), 0)
        EVT_BUTTON(self, self.ID_GOBUTTON, self.button_convert)
        mainsizer.Add(sz,0,wxALL|wxALIGN_RIGHT,5)

        self.SetAutoLayout(true)
        self.SetSizer(mainsizer)
        
    #
    # ADVANCED OPTIONS
    # A lot of these are more restricted versions of what the plugins can do.
    # Oh well, such is life when you insist on a GUI instead of using the
    # shell like a real man :)
    #
    ID_CHECK_INSTALL = 300
    ID_PICK_DOC_OUTPUT = 301
    ID_PICK_TEXT_PARSER = 302
    ID_CHECK_COPYDOC = 303
    ID_PICK_DOC_ASSEMBLER = 304
    
    def init_advanced_options(self):
        # advanced options
        opts = wxStaticBox(self, -1, "Advanced Options")
        sz0 = wxStaticBoxSizer(opts, wxVERTICAL)

        sz = wxFlexGridSizer(0,2,5,5)
        sz.AddGrowableCol(0)
        sz.AddGrowableCol(1)

        # ** Queue for installation ; sets the "install" property on every plugin with it
        # and disables the output file box if present
        if self.instance.find_installer() is not None:
            self.check_install = wxCheckBox(self, self.ID_CHECK_INSTALL, "Queue for installation")
            sz.Add(self.check_install)
        else:
            self.check_install = None
        #EVT_CHECKBOX(self, self.ID_CHECK_INSTALL, self.toggle_install)

        # ** Default doc output method: looks for plugins with doc-output
        # and lets you pick one, and forces it
        #z = wxBoxSizer(wxHORIZONTAL)
        #pnames = [ p.name for p in self.instance.find_plugins_with_link('doc-output') ]
        #pnames.insert(0,"<Automatic>")
        #z.Add(wxStaticText(self, -1, "Doc Output:"), 0, wxALIGN_CENTER_VERTICAL)
        #self.pick_docoutput = wxChoice(self, self.ID_PICK_DOC_OUTPUT, wxDefaultPosition,
        #                               wxDefaultSize,
        #                               pnames)
        #z.Add(self.pick_docoutput, 1)
        #self.pick_docoutput.SetSelection(0)
        #sz.Add(z, 1, wxEXPAND)

        # ** Copy docs directly: Forces the CopyDoc plugin
        self.check_copydoc = wxCheckBox(self, self.ID_CHECK_COPYDOC, "Copy Docs directly")
        sz.Add(self.check_copydoc)

        # ** Doc format: lets you pick a doc-assembler
        #z = wxBoxSizer(wxHORIZONTAL)
        #pnames = [ p.name for p in self.instance.find_plugins_with_link('doc-assembler') ]
        #pnames.insert(0, "<Automatic>")
        #z.Add(wxStaticText(self, -1, "Doc Format:"), 0, wxALIGN_CENTER_VERTICAL)
        #self.pick_docassembler = wxChoice(self, self.ID_PICK_DOC_ASSEMBLER, wxDefaultPosition,
        #                                  wxDefaultSize,
        #                                  pnames)
        #z.Add(self.pick_docassembler, 1)
        #self.pick_docassembler.SetSelection(0)
        #sz.Add(z, 1, wxEXPAND)

        sz.Add(wxStaticText(self, -1, "")) # empty
        
        # ** Default text conversion method: looks for plugins with text/plain and
        # lets you pick one
        #z = wxBoxSizer(wxHORIZONTAL)
        #pnames = [ p.name for p in self.instance.find_plugins_with_link('text/plain') ]
        #pnames.insert(0, "<Automatic>")
        #z.Add(wxStaticText(self, -1, "Text Parser:"), 0, wxALIGN_CENTER_VERTICAL)
        #self.pick_textparser = wxChoice(self, self.ID_PICK_TEXT_PARSER, wxDefaultPosition,
        #                                wxDefaultSize,
        #                                pnames)
        #z.Add(self.pick_textparser, 1)
        #self.pick_textparser.SetSelection(0)
        #sz.Add(z, 1, wxEXPAND)

        sz0.Add(sz,1,wxEXPAND)
        return sz0


    def do_options(self):
        # properties
        if self.check_install is not None and self.check_install.GetValue():
            self.instance.set_property_all('install',1)
        else:
            self.instance.set_property_all('install',0)
        self.instance.set_property_all('output_filename',self.ctrl_outfile.GetValue())

        # task (if any)
        n = self.pick_task.GetSelection()
        print n
        if n:
            k,task = self.tasks[n-1]
            forced_plugins = task.plugins[:]
            for k,v in task.properties.items():
                print "Task property:", k, "=", v
                self.set_property_all(k,v)
        else:
            forced_plugins = []
            
        # forced plugins
        if self.check_copydoc.GetValue():
            forced_plugins.append('CopyDoc')
        #p.append(self.pick_docoutput.GetStringSelection())
        #p.append(self.pick_docassembler.GetStringSelection())
        #p.append(self.pick_textparser.GetStringSelection())

        fp = [self.instance.plugins[x] for x in forced_plugins]
        return fp
    
    #################################################
    def menu_exit(self, event):
        self.Close(true)

    def menu_about(self, event):
        dlg = wxMessageDialog(self, "Pyrite Publisher %s\nby Rob Tillotson <rob@pyrite.org>\nhttp://www.pyrite.org/" % dtkmain.VERSION,
                              "About Pyrite Publisher", wxOK)
        dlg.ShowModal()
        dlg.Destroy()

    def menu_plugins(self, event):
        dlg = PPPluginBrowser(self, self.instance)
        dlg.Show(true)
        
    def button_chooseinput(self, event):
        wc = self.instance.wildcards.items()
        wc.sort(lambda x,y: cmp(x[1],y[1]))
        wc.insert(0, ('*.*', 'All files'))
        wct = '|'.join(map(lambda p: '%s (%s)|%s' % (p[1],p[0],p[0]), wc))
        
        dlg = wxFileDialog(self, "Choose a file to convert",
                           wildcard = wct, style=wxOPEN)
        if dlg.ShowModal() == wxID_OK:
            ifn = dlg.GetPath()
            self.ctrl_infile.SetValue(ifn)
            self.ctrl_outfile.SetValue('')
        dlg.Destroy()
        
    def button_chooseoutput(self, event):
        dlg = wxFileDialog(self, "Choose an output filename", wildcard="All files (*.*)|*.*",
                           style=wxSAVE)
        if dlg.ShowModal() == wxID_OK:
            ofn = dlg.GetPath()
            self.ctrl_outfile.SetValue(ofn)
        dlg.Destroy()
        
    
    def button_convert(self, event):
        fname = self.ctrl_infile.GetValue()
        self.SetStatusText("Converting %s..." % fname)

        forced = self.do_options()
        try:
            self.instance.convert_file(fname, forced)
        except dtkmain.ConversionError, err:
            dlg = wxMessageDialog(self, str(err), "Conversion Error",
                                  wxOK|wxICON_EXCLAMATION)
            dlg.ShowModal()
            dlg.Destroy()
        except:
            t, v, tb = sys.exc_info()
            dlg = wxMessageDialog(self, "%s: %s" % (t,v), "Error",
                                  wxOK|wxICON_EXCLAMATION)
            dlg.ShowModal()
            dlg.Destroy()

        self.SetStatusText("Done.")


        
class PPApp(wxApp,dtkmain.PPInstance):
    def __init__(self, *a, **kw):
        dtkmain.PPInstance.__init__(self)
        wxApp.__init__(self, *a, **kw)
        
    def OnInit(self):
        frame = PPMainFrame(NULL, -1, "Pyrite Publisher", instance=self)
        frame.Show(true)
        self.SetTopWindow(frame)
        return true


if __name__ == '__main__':
    app = PPApp(0)
    app.MainLoop()
    
