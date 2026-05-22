# -*- coding: utf-8 -*-
"""
JS Analyzer - Results Panel
Modernized UI with Split Pane, Preview, and Source Viewer.
"""

from javax.swing import (
    JPanel, JScrollPane, JTabbedPane, JButton, JLabel,
    JTable, JComboBox, JTextField, BorderFactory, JSplitPane,
    JTextArea, Box, JDialog, JFrame, SwingUtilities, AbstractAction
)
from javax.swing.event import ListSelectionListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import (
    BorderLayout, FlowLayout, Font, Dimension, Toolkit, 
    Color, GridBagLayout, GridBagConstraints, Insets
)
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, KeyListener, KeyEvent, MouseAdapter
from javax.swing import KeyStroke # Added for KeyStroke
from threading import Thread
import json


class ResultsPanel(JPanel):
    """Modernized results panel with search, filtering, and source viewer."""
    
    def __init__(self, callbacks, extender):
        JPanel.__init__(self)
        self.callbacks = callbacks
        self.extender = extender
        
        # Dark Theme Colors
        self.BACKGROUND_DARK = Color(30, 30, 30)
        self.BACKGROUND_LIGHT = Color(45, 45, 45)
        self.TEXT_PRIMARY = Color(220, 220, 200)
        self.TEXT_SECONDARY = Color(180, 180, 180)
        self.ACCENT_COLOR = Color(100, 180, 255)
        self.SELECTION_COLOR = Color(60, 60, 70)
        self.BORDER_COLOR = Color(60, 60, 60)
        
        self.TITLE_FONT = Font("SansSerif", Font.BOLD, 14)
        self.LABEL_FONT = Font("SansSerif", Font.PLAIN, 12)
        self.MONO_FONT = Font("Monospaced", Font.PLAIN, 12)
        
        # Store tables for access
        self.tables = {}
        self.models = {}

        # Findings by category
        self.findings = {
            "endpoints": [],
            "urls": [],
            "secrets": [],
            "emails": [],
            "files": [],
            "cloud": [],
            "subdomains": [],
            "keywords": [],
            "dom_sinks": [],
        }
        
        self.sources = set()
        self._init_ui()
    
    def _init_ui(self):
        """Build the modernized Dark Mode UI."""
        self.setLayout(BorderLayout(0, 0))
        self.setBackground(self.BACKGROUND_DARK)
        
        # ===== TOP BAR: Header & Search =====
        top_panel = JPanel(BorderLayout(10, 5))
        top_panel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, self.BORDER_COLOR))
        top_panel.setBackground(self.BACKGROUND_LIGHT)
        
        # Title and Stats
        title_box = Box.createHorizontalBox()
        app_title = JLabel("JS ANALYZER")
        app_title.setFont(self.TITLE_FONT)
        app_title.setForeground(self.ACCENT_COLOR)
        title_box.add(app_title)
        title_box.add(Box.createHorizontalStrut(15))
        
        self.stats_label = JLabel("E:0 | U:0 | S:0 | M:0 | F:0")
        self.stats_label.setFont(self.LABEL_FONT)
        self.stats_label.setForeground(self.TEXT_SECONDARY)
        title_box.add(self.stats_label)
        title_box.add(Box.createHorizontalStrut(15))
        self.progress_label = JLabel("")
        self.progress_label.setFont(self.LABEL_FONT)
        self.progress_label.setForeground(Color(100, 255, 100))
        title_box.add(self.progress_label)
        top_panel.add(title_box, BorderLayout.WEST)
        
        # Filters
        filter_box = Box.createHorizontalBox()
        l_search = JLabel("Search: ")
        l_search.setForeground(self.TEXT_PRIMARY)
        filter_box.add(l_search)
        
        self.search_field = JTextField(20)
        self.search_field.setBackground(Color(60, 60, 60))
        self.search_field.setForeground(Color.WHITE)
        self.search_field.setCaretColor(Color.WHITE)
        self.search_field.setBorder(BorderFactory.createLineBorder(self.BORDER_COLOR))
        self.search_field.addKeyListener(SearchKeyListener(self))
        filter_box.add(self.search_field)
        
        filter_box.add(Box.createHorizontalStrut(15))
        l_source = JLabel("Source: ")
        l_source.setForeground(self.TEXT_PRIMARY)
        filter_box.add(l_source)
        
        self.source_filter = JComboBox(["All Sources"])
        self.source_filter.setPreferredSize(Dimension(200, 25))
        self.source_filter.setBackground(Color(60, 60, 60))
        self.source_filter.setForeground(Color.WHITE)
        self.source_filter.addActionListener(FilterAction(self))
        filter_box.add(self.source_filter)
        top_panel.add(filter_box, BorderLayout.EAST)
        
        self.add(top_panel, BorderLayout.NORTH)
        
        # ===== CENTER: Split Pane with Tabs & Preview =====
        self.tabs = JTabbedPane()
        self.tabs.setFont(self.LABEL_FONT)
        
        self.tables = {}
        self.models = {}
        
        categories = [
            ("Endpoints", "endpoints"),
            ("URLs", "urls"),
            ("Secrets", "secrets"),
            ("Emails", "emails"),
            ("Files", "files"),
            ("Cloud", "cloud"),
            ("Subdomains", "subdomains"),
            ("Keywords", "keywords"),
            ("DOM Sinks", "dom_sinks"),
        ]
        
        for title, key in categories:
            panel = JPanel(BorderLayout())
            panel.setBackground(self.BACKGROUND_DARK)
            columns = ["Value", "Source", "Detail", "Metadata"]
            model = NonEditableTableModel(columns, 0)
            self.models[key] = model
            
            table = JTable(model)
            self.tables[key] = table
            # Hide Metadata column
            table.getColumnModel().removeColumn(table.getColumnModel().getColumn(3))
            
            table.setAutoCreateRowSorter(True)
            table.setFont(self.MONO_FONT)
            table.setRowHeight(25)
            table.setBackground(self.BACKGROUND_DARK)
            table.setForeground(self.TEXT_PRIMARY)
            table.setGridColor(self.BORDER_COLOR)
            
            # Setup "Value Only" Selection Logic & Visuals
            table.setSelectionBackground(self.SELECTION_COLOR)
            table.setSelectionForeground(Color.WHITE)
            table.setCellSelectionEnabled(True)
            table.setColumnSelectionAllowed(True)
            table.setRowSelectionAllowed(True) # Required for getSelectedRow/Rows logic
            
            # Apply renderer to all columns to hide selection on non-value columns
            renderer = ValueSelectionRenderer(self.SELECTION_COLOR, self.BACKGROUND_DARK, self.TEXT_PRIMARY)
            for i in range(3): # Value, Source, Detail
                table.getColumnModel().getColumn(i).setCellRenderer(renderer)
            
            # Header styling
            header = table.getTableHeader()
            header.setBackground(self.BACKGROUND_LIGHT)
            header.setForeground(self.TEXT_PRIMARY)
            header.setFont(self.LABEL_FONT)
            
            # Disable default JTable copy behavior to enforce our clean value-only copy
            table.setTransferHandler(None)
            
            # Use ActionMap for Ctrl+C instead of KeyListener for reliability
            input_map = table.getInputMap(JTable.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
            action_map = table.getActionMap()
            
            # Override "copy" action
            input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_C, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()), "copy")
            action_map.put("copy", CopyAction(self))
            
            # Override "select all" action (Ctrl+A)
            input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_A, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()), "selectAll")
            action_map.put("selectAll", SelectAllAction(self))
            
            # Listeners & Actions
            table.getSelectionModel().addListSelectionListener(TableSelectionListener(self, table))
            table.addMouseListener(TableMouseListener(self, table))
            
            scroll = JScrollPane(table)
            scroll.setBackground(self.BACKGROUND_DARK)
            scroll.getViewport().setBackground(self.BACKGROUND_DARK)
            scroll.setBorder(BorderFactory.createEmptyBorder())
            panel.add(scroll, BorderLayout.CENTER)
            self.tabs.addTab(title + " (0)", panel)

        # Preview Panel
        preview_container = JPanel(BorderLayout())
        preview_container.setBackground(self.BACKGROUND_DARK)
        btn_border = BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(self.BORDER_COLOR), "Detail Preview"
        )
        btn_border.setTitleColor(self.ACCENT_COLOR)
        preview_container.setBorder(btn_border)
        
        self.preview_area = JTextArea(5, 50)
        self.preview_area.setEditable(False)
        self.preview_area.setFont(self.MONO_FONT)
        self.preview_area.setBackground(Color(25, 25, 25))
        self.preview_area.setForeground(self.TEXT_PRIMARY)
        self.preview_area.setCaretColor(Color.WHITE)
        self.preview_area.setLineWrap(True)
        self.preview_area.setWrapStyleWord(True)
        
        scroll_preview = JScrollPane(self.preview_area)
        scroll_preview.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        scroll_preview.setBackground(Color(25, 25, 25))
        preview_container.add(scroll_preview, BorderLayout.CENTER)
        
        # Split Pane
        self.split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.tabs, preview_container)
        self.split_pane.setDividerLocation(400)
        self.split_pane.setResizeWeight(0.8)
        self.split_pane.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5))
        
        self.add(self.split_pane, BorderLayout.CENTER)
        
        # ===== BOTTOM BAR: Actions =====
        bottom_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 10, 10))
        bottom_panel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, self.BORDER_COLOR))
        bottom_panel.setBackground(self.BACKGROUND_LIGHT)
        
        def style_btn(btn):
            btn.setBackground(Color(60, 60, 60))
            btn.setForeground(Color.WHITE)
            btn.setFocusPainted(False)
            btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(self.BORDER_COLOR),
                BorderFactory.createEmptyBorder(5, 10, 5, 10)
            ))
        
        view_btn = JButton("View Source Code")
        style_btn(view_btn)
        view_btn.addActionListener(ViewSourceAction(self))
        bottom_panel.add(view_btn)
        
        copy_btn = JButton("Copy Selected")
        style_btn(copy_btn)
        copy_btn.addActionListener(CopyAction(self))
        bottom_panel.add(copy_btn)
        
        copy_all_btn = JButton("Copy All Visible")
        style_btn(copy_all_btn)
        copy_all_btn.addActionListener(CopyAllAction(self))
        bottom_panel.add(copy_all_btn)
        
        clear_btn = JButton("Clear Results")
        style_btn(clear_btn)
        clear_btn.addActionListener(ClearAction(self))
        bottom_panel.add(clear_btn)
        
        export_btn = JButton("Export Results")
        style_btn(export_btn)
        export_btn.addActionListener(ExportAction(self))
        bottom_panel.add(export_btn)
        
        self.add(bottom_panel, BorderLayout.SOUTH)
    
    def set_progress(self, text):
        """Show progress text during analysis."""
        def update():
            self.progress_label.setText(text)
        SwingUtilities.invokeLater(update)

    def add_findings(self, new_findings, source_name):
        """Add new findings and update UI."""
        def update():
            self.progress_label.setText("")
            if source_name and source_name not in self.sources:
                self.sources.add(source_name)
                self.source_filter.addItem(source_name)
            
            for finding in new_findings:
                category = finding.get("category", "")
                if category in self.findings:
                    self.findings[category].append({
                        "value": finding.get("value", ""),
                        "source": finding.get("source", source_name), # Filename for UI
                        "url": finding.get("url", ""),              # mapping key
                        "offset": finding.get("offset", 0),
                        "detail": finding.get("detail", ""),
                    })
            
            self._refresh_tables()
        
        SwingUtilities.invokeLater(update)
    
    def _refresh_tables(self):
        """Refresh tables with current filters."""
        # This is typically called from within invokeLater via add_findings or clear_all
        # but safe to wrap again or ensure it's on EDT if called directly
        if not SwingUtilities.isEventDispatchThread():
            SwingUtilities.invokeLater(self._refresh_tables)
            return

        selected_source = str(self.source_filter.getSelectedItem())
        search_text = self.search_field.getText().lower().strip()
        
        titles = ["Endpoints", "URLs", "Secrets", "Emails", "Files", "Cloud", "Subdomains", "Keywords", "DOM Sinks"]
        keys = ["endpoints", "urls", "secrets", "emails", "files", "cloud", "subdomains", "keywords", "dom_sinks"]
        
        for i, (title, key) in enumerate(zip(titles, keys)):
            model = self.models[key]
            model.setRowCount(0)
            
            count = 0
            # Store metadata in a hidden way or use index mapping
            filtered_items = []
            for item in self.findings.get(key, []):
                # Source filter
                if selected_source != "All Sources" and item.get("source") != selected_source:
                    continue
                
                # Search filter
                if search_text:
                    if search_text not in item.get("value", "").lower() and \
                       search_text not in item.get("detail", "").lower():
                        continue
                
                model.addRow([
                    item.get("value", ""), 
                    item.get("source", ""), 
                    item.get("detail", ""),
                    item # Store the full finding object as metadata
                ])
                count += 1
            
            self.tabs.setTitleAt(i, "%s (%d)" % (title, count))
        
        self._update_stats()
    
    def _update_stats(self):
        """Update metrics label with total count."""
        e = len(self.findings.get("endpoints", []))
        u = len(self.findings.get("urls", []))
        s = len(self.findings.get("secrets", []))
        m = len(self.findings.get("emails", []))
        f = len(self.findings.get("files", []))
        c = len(self.findings.get("cloud", []))
        d = len(self.findings.get("subdomains", []))
        k = len(self.findings.get("keywords", []))
        x = len(self.findings.get("dom_sinks", []))
        total = e + u + s + m + f + c + d + k + x
        self.stats_label.setText("TOTAL:%d | E:%d | U:%d | S:%d | M:%d | F:%d | C:%d | D:%d | K:%d | X:%d" % (total, e, u, s, m, f, c, d, k, x))
    
    def update_preview(self, text):
        """Update the preview text area."""
        def update():
            self.preview_area.setText(text)
            self.preview_area.setCaretPosition(0)
        SwingUtilities.invokeLater(update)

    def view_source_for_selected(self):
        """Open source viewer for selected finding using hidden metadata."""
        table = self._get_current_table()
        if not table or table.getSelectedRow() < 0:
            return
            
        model_row = table.convertRowIndexToModel(table.getSelectedRow())
        # Column 3 is the hidden Metadata column
        item = table.getModel().getValueAt(model_row, 3)
        
        if item:
            # item["url"] is the full URL for mapping
            source_content = self.extender.get_source_code(item.get("url", ""))
            if source_content:
                SourceViewerDialog(None, 
                                 item.get("source", "Unknown"), source_content, 
                                 item.get("offset", 0), len(str(item.get("value", "")))).setVisible(True)

    def _get_current_table(self):
        idx = self.tabs.getSelectedIndex()
        keys = ["endpoints", "urls", "secrets", "emails", "files", "cloud", "subdomains", "keywords", "dom_sinks"]
        if 0 <= idx < len(keys):
            if not hasattr(self, 'tables'):
                self.tables = {}
            return self.tables.get(keys[idx])
        return None

    def _get_current_key(self):
        idx = self.tabs.getSelectedIndex()
        keys = ["endpoints", "urls", "secrets", "emails", "files", "cloud", "subdomains", "keywords", "dom_sinks"]
        if 0 <= idx < len(keys):
            return keys[idx]
        return None

    def _copy_to_clipboard(self, text):
        """
        Robust clipboard copy using SwingUtilities.invokeLater.
        Fallback to stdout if clipboard fails.
        """
        if not text: return
        
        # 1. Print to console as backup (so user can always get the data)
        print("[INFO] Copy command received (%d chars)." % len(text))
        
        def do_copy():
            try:
                from java.awt import Toolkit
                from java.awt.datatransfer import StringSelection
                from java.lang import Throwable
                
                # Unicode safety
                val = text if isinstance(text, unicode) else str(text).decode('utf-8', 'ignore')
                selection = StringSelection(val)
                
                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                clipboard.setContents(selection, selection)
                print("[SUCCESS] Copied to system clipboard.")
            except (Exception, Throwable) as e:
                print("[ERROR] Clipboard access failed: " + str(e))
                # Fallback to UI Dialog
                self._show_copy_dialog(text)
                
        # Run on EDT to ensure AWT/Swing compatibility
        SwingUtilities.invokeLater(do_copy)

    def _show_copy_dialog(self, text):
        """Show a dialog with text selected for manual copying."""
        dialog = JDialog(SwingUtilities.getWindowAncestor(self), "Copy to Clipboard", True)
        dialog.setSize(500, 400)
        dialog.setLocationRelativeTo(self)
        dialog.setLayout(BorderLayout())
        
        area = JTextArea(text)
        area.setFont(self.MONO_FONT)
        area.setEditable(False)
        area.setLineWrap(True)
        area.setWrapStyleWord(True)
        
        # Select all text for easy copying
        area.selectAll()
        area.requestFocusInWindow()
        
        scroll = JScrollPane(area)
        dialog.add(scroll, BorderLayout.CENTER)
        
        lbl = JLabel("  System clipboard halted. Press Ctrl+C to copy manually.")
        lbl.setForeground(self.ACCENT_COLOR) # Re-use styling
        dialog.add(lbl, BorderLayout.NORTH)
        
        btn = JButton("Close")
        btn.addActionListener(lambda e: dialog.dispose())
        dialog.add(btn, BorderLayout.SOUTH)
        
        dialog.setVisible(True)

    def copy_selected(self, table=None):
        """Copy ONLY the Value column for all selected rows."""
        print("[DEBUG] copy_selected triggered")
        if not table:
            table = self._get_current_table()
        if not table:
            print("[DEBUG] No table found")
            return
            
        selected_rows = table.getSelectedRows()
        print("[DEBUG] Selected rows count: %d" % len(selected_rows))
        if not selected_rows:
            return
            
        values = []
        for view_row in selected_rows:
            model_row = table.convertRowIndexToModel(view_row)
            value = table.getModel().getValueAt(model_row, 0)
            if value:
                # Handle potential unicode/bytes mix
                v = value
                if not isinstance(v, unicode):
                    v = str(v).decode('utf-8', 'ignore')
                values.append(v.strip())
        
        print("[DEBUG] Extracted values count: %d" % len(values))
        if values:
            final_text = "\n".join(values)
            print("[DEBUG] Sending %d chars to clipboard" % len(final_text))
            self._copy_to_clipboard(final_text)

    def copy_all_visible(self):
        table = self._get_current_table()
        if table:
            model = table.getModel()
            values = []
            for i in range(model.getRowCount()):
                val = model.getValueAt(i, 0)
                if val:
                    if not isinstance(val, unicode):
                        val = str(val).decode('utf-8', 'ignore')
                    values.append(val.strip())
            if values:
                self._copy_to_clipboard("\n".join(values))

    def clear_all(self):
        def update():
            for key in self.findings:
                self.findings[key] = []
            self.sources = set()
            self.source_filter.removeAllItems()
            self.source_filter.addItem("All Sources")
            self.search_field.setText("")
            self.preview_area.setText("")
            self.extender.clear_results()
            self._refresh_tables()
        SwingUtilities.invokeLater(update)

    def export_all(self):
        from javax.swing import JFileChooser, JOptionPane
        from java.io import File
        
        # Ask format
        options = ["JSON (Detailed)", "JSON (Values Only)", "CSV"]
        choice = JOptionPane.showOptionDialog(
            self, "Select export format:", "Export Findings",
            JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
            None, options, options[0]
        )
        if choice < 0: return
        
        ext = ".csv" if choice == 2 else ".json"
        chooser = JFileChooser()
        chooser.setSelectedFile(File("js_findings" + ext))
        if chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            
            if choice == 0:  # Detailed JSON
                export = {}
                for k, v in self.findings.items():
                    export[k] = [{"value": f.get("value",""), "source": f.get("source",""), 
                                  "detail": f.get("detail",""), "url": f.get("url","")} for f in v]
                export["_meta"] = {"total": sum(len(v) for v in self.findings.values()),
                                   "sources": list(self.sources)}
                with open(path, 'w') as f:
                    json.dump(export, f, indent=2)
            elif choice == 1:  # Values only JSON
                export = {k: [f["value"] for f in v] for k, v in self.findings.items()}
                with open(path, 'w') as f:
                    json.dump(export, f, indent=2)
            else:  # CSV
                with open(path, 'w') as f:
                    f.write("Category,Value,Source,Detail\n")
                    for k, findings in self.findings.items():
                        for item in findings:
                            val = str(item.get("value","")).replace('"', '""')
                            src = str(item.get("source","")).replace('"', '""')
                            det = str(item.get("detail","")).replace('"', '""')
                            f.write('"%s","%s","%s","%s"\n' % (k, val, src, det))


class ValueSelectionRenderer(DefaultTableCellRenderer):
    """Renderer with selection highlighting and severity color-coding for secrets."""
    
    SEVERITY_COLORS = {
        "CRITICAL": Color(180, 40, 40),    # Deep red
        "HIGH": Color(200, 120, 30),       # Orange
        "MEDIUM": Color(180, 180, 50),     # Yellow-ish
        "LOW": Color(80, 160, 80),         # Green
    }
    
    def __init__(self, selection_bg, normal_bg, normal_fg):
        DefaultTableCellRenderer.__init__(self)
        self.selection_bg = selection_bg
        self.normal_bg = normal_bg
        self.normal_fg = normal_fg

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        
        if isSelected and column == 0:
            c.setBackground(self.selection_bg)
            c.setForeground(Color.WHITE)
        else:
            # Check for severity in detail column (column 2) for color coding
            bg = self.normal_bg
            fg = self.normal_fg
            try:
                model_row = table.convertRowIndexToModel(row)
                detail = str(table.getModel().getValueAt(model_row, 2) or "")
                if detail.startswith("[CRITICAL]"):
                    bg = Color(60, 20, 20)
                    fg = Color(255, 120, 120)
                elif detail.startswith("[HIGH]"):
                    bg = Color(50, 35, 15)
                    fg = Color(255, 180, 80)
                elif detail.startswith("[MEDIUM]"):
                    bg = Color(45, 45, 20)
                    fg = Color(230, 230, 100)
                elif detail.startswith("[LOW]"):
                    bg = Color(20, 45, 20)
                    fg = Color(120, 220, 120)
            except:
                pass
            c.setBackground(bg)
            c.setForeground(fg)
            
        c.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10))
        return c


class NonEditableTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False


class SourceViewerDialog(JDialog):
    """Dialog to view source code and highlight finding."""
    def __init__(self, parent, title, content, offset, length):
        JDialog.__init__(self, parent, "Source Viewer - " + title, True)
        self.setSize(900, 700)
        self.setLocationRelativeTo(parent)
        self.setLayout(BorderLayout())
        
        # Colors (Dark Mode)
        bg = Color(30, 30, 30)
        fg = Color(220, 220, 200)
        highlight = Color(0, 102, 204, 100) # Semi-transparent blue
        
        # Add line numbers to content
        numbered_lines = []
        for i, line in enumerate(content.split('\n'), 1):
            numbered_lines.append("%4d | %s" % (i, line))
        numbered_content = '\n'.join(numbered_lines)
        
        area = JTextArea(numbered_content)
        area.setEditable(False)
        area.setBackground(bg)
        area.setForeground(fg)
        area.setFont(Font("Monospaced", Font.PLAIN, 12))
        area.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        area.setCaretColor(Color.WHITE)
        
        # Highlight and Scroll
        try:
            if offset >= 0:
                from javax.swing.text import DefaultHighlighter
                # More prominent highlight: semi-transparent yellow
                painter = DefaultHighlighter.DefaultHighlightPainter(Color(255, 255, 0, 100))
                area.getHighlighter().addHighlight(offset, offset + length, painter)
                
                # Scroll to location with multi-step reliability
                def scroll_to():
                    try:
                        area.setCaretPosition(offset)
                        view_rect = area.modelToView(offset)
                        if view_rect:
                            # Scroll a bit higher than the line for context
                            view_rect.y = max(0, view_rect.y - 100)
                            view_rect.height += 200
                            area.scrollRectToVisible(view_rect)
                    except: pass
                
                SwingUtilities.invokeLater(scroll_to)
        except: pass
            
        scroll = JScrollPane(area)
        scroll.setBorder(None)
        self.add(scroll, BorderLayout.CENTER)
        
        # Bottom bar info
        line_num = content[:offset].count('\n') + 1
        info = JLabel(" Location: Line %d, Offset %d" % (line_num, offset))
        info.setForeground(Color.LIGHT_GRAY)
        info.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        self.add(info, BorderLayout.SOUTH)


class TableSelectionListener(ListSelectionListener):
    """Updates preview when a row is selected."""
    def __init__(self, panel, table):
        self.panel = panel
        self.table = table
    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            row = self.table.getSelectedRow()
            if row >= 0:
                try:
                    model_row = self.table.convertRowIndexToModel(row)
                    value = self.table.getModel().getValueAt(model_row, 0)
                    detail = self.table.getModel().getValueAt(model_row, 2)
                    source = self.table.getModel().getValueAt(model_row, 1)
                    if value:
                        preview = "Value: %s" % str(value).strip()
                        if detail:
                            preview += "\nDetail: %s" % str(detail).strip()
                        if source:
                            preview += "\nSource: %s" % str(source).strip()
                        self.panel.update_preview(preview)
                except: pass


class TableMouseListener(MouseAdapter):
    """Detect double-click on table rows."""
    def __init__(self, panel, table):
        self.panel = panel
        self.table = table
    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self.panel.view_source_for_selected()


class SearchKeyListener(KeyListener):
    def __init__(self, panel):
        self.panel = panel
    def keyReleased(self, event):
        self.panel._refresh_tables()
    def keyPressed(self, event): pass
    def keyTyped(self, event): pass


class TableKeyListener(KeyListener):
    """Handle Ctrl+C for table copying."""
    def __init__(self, panel):
        self.panel = panel
        
    def keyPressed(self, event):
        if event.isControlDown():
            if event.getKeyCode() == KeyEvent.VK_C:
                self.panel.copy_selected(event.getSource())
                event.consume()
            elif event.getKeyCode() == KeyEvent.VK_A:
                # Custom Select All: only select the Value column
                table = event.getSource()
                if table.getRowCount() > 0:
                    table.setColumnSelectionInterval(0, 0)
                    table.setRowSelectionInterval(0, table.getRowCount() - 1)
                event.consume()
            
    def keyReleased(self, event): pass
    def keyTyped(self, event): pass


class FilterAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel._refresh_tables()


class ViewSourceAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.view_source_for_selected()


class CopyAction(AbstractAction):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.copy_selected()

class SelectAllAction(AbstractAction):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        # Programmatically select all rows in current table
        table = self.panel._get_current_table()
        if table and table.getRowCount() > 0:
            table.setRowSelectionInterval(0, table.getRowCount() - 1)
            # Optional: Select only first column to match "Value Only" feel
            table.setColumnSelectionInterval(0, 0)


class CopyAllAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.copy_all_visible()


class ClearAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.clear_all()


class ExportAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.export_all()
