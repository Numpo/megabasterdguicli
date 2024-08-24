/*
 __  __                  _               _               _ 
|  \/  | ___  __ _  __ _| |__   __ _ ___| |_ ___ _ __ __| |
| |\/| |/ _ \/ _` |/ _` | '_ \ / _` / __| __/ _ \ '__/ _` |
| |  | |  __/ (_| | (_| | |_) | (_| \__ \ ||  __/ | | (_| |
|_|  |_|\___|\__, |\__,_|_.__/ \__,_|___/\__\___|_|  \__,_|
             |___/                                         
© Perpetrated by tonikelope since 2016
 */
package com.tonikelope.megabasterd;

import javax.swing.*;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeNode;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static com.tonikelope.megabasterd.MainPanel.GUI_FONT;
import static com.tonikelope.megabasterd.MainPanel.THREAD_POOL;
import static com.tonikelope.megabasterd.MiscTools.cleanFilePath;
import static com.tonikelope.megabasterd.MiscTools.deleteAllExceptSelectedTreeItems;
import static com.tonikelope.megabasterd.MiscTools.deleteSelectedTreeItems;
import static com.tonikelope.megabasterd.MiscTools.findFirstRegex;
import static com.tonikelope.megabasterd.MiscTools.formatBytes;
import static com.tonikelope.megabasterd.MiscTools.translateLabels;
import static com.tonikelope.megabasterd.MiscTools.updateFonts;
import static java.util.logging.Level.SEVERE;

/**
 * @author tonikelope
 */
public class FolderLinkDialog extends javax.swing.JDialog {

    private final String _link;

    private boolean _download;

    private final List<HashMap> _download_links;

    private long _total_space;

    private int _mega_error;

    private volatile boolean working = false;

    private volatile boolean exit = false;

    @Override
    public void dispose() {
        this.file_tree.setModel(null);
        super.dispose();
    }

    public List<HashMap> getDownload_links() {
        return Collections.unmodifiableList(this._download_links);
    }

    public boolean isDownload() {
        return this._download;
    }

    public int isMega_error() {
        return this._mega_error;
    }

    /**
     * Creates new form FolderLink
     *
     * @param parent
     * @param link
     */
    public FolderLinkDialog(final MainPanelView parent, final boolean modal, final String link) {

        super(parent, modal);

        this._mega_error = 0;
        this._total_space = 0L;
        this._download = false;
        this._download_links = new ArrayList<>();
        this._link = link;

        MiscTools.GUIRunAndWait(() -> {

            this.initComponents();

            updateFonts(this, GUI_FONT, parent.getMain_panel().getZoom_factor());

            translateLabels(this);

            this.file_tree.setRootVisible(false);

            this.node_bar.setIndeterminate(true);

            this.folder_link_label.setText(link);

            this.restore_button.setVisible(false);

            final Dialog tthis = this;

            THREAD_POOL.execute(() -> {
                this._loadMegaDirTree();

                if (this._mega_error == 0) {

                    this._genDownloadLiks();

                    MiscTools.GUIRun(() -> {

                        this.dance_button.setText(LabelTranslatorSingleton.getInstance().translate("Let's dance, baby"));

                        this.pack();
                    });

                } else if (this._mega_error == -18) {

                    MiscTools.GUIRun(() -> {
                        JOptionPane.showMessageDialog(tthis, LabelTranslatorSingleton.getInstance().translate("MEGA FOLDER TEMPORARILY UNAVAILABLE!"), "Error", JOptionPane.ERROR_MESSAGE);

                        this.setVisible(false);
                    });

                } else if (this._mega_error == -16) {

                    MiscTools.GUIRun(() -> {
                        JOptionPane.showMessageDialog(tthis, LabelTranslatorSingleton.getInstance().translate("MEGA FOLDER BLOCKED/DELETED"), "Error", JOptionPane.ERROR_MESSAGE);

                        this.setVisible(false);
                    });

                } else {

                    MiscTools.GUIRun(() -> {
                        JOptionPane.showMessageDialog(tthis, LabelTranslatorSingleton.getInstance().translate("MEGA FOLDER LINK ERROR!"), "Error", JOptionPane.ERROR_MESSAGE);

                        this.setVisible(false);
                    });
                }
            });

            this.pack();

        });
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        this.file_tree_scrollpane = new javax.swing.JScrollPane();
        this.skip_button = new javax.swing.JButton();
        this.link_detected_label = new javax.swing.JLabel();
        this.dance_button = new javax.swing.JButton();
        this.folder_link_label = new javax.swing.JLabel();
        this.warning_label = new javax.swing.JLabel();
        this.skip_rest_button = new javax.swing.JButton();
        this.restore_button = new javax.swing.JButton();
        this.total_space_label = new javax.swing.JLabel();
        this.node_bar = new javax.swing.JProgressBar();

        this.setDefaultCloseOperation(javax.swing.WindowConstants.DO_NOTHING_ON_CLOSE);
        this.setTitle("FolderLink");
        this.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(final java.awt.event.WindowEvent evt) {
                FolderLinkDialog.this.formWindowClosing(evt);
            }
        });

        this.file_tree.setFont(new java.awt.Font("Dialog", 0, 18)); // NOI18N
        final javax.swing.tree.DefaultMutableTreeNode treeNode1 = new javax.swing.tree.DefaultMutableTreeNode("root");
        this.file_tree.setModel(new javax.swing.tree.DefaultTreeModel(treeNode1));
        this.file_tree.setDoubleBuffered(true);
        this.file_tree.setEnabled(false);
        this.file_tree_scrollpane.setViewportView(this.file_tree);

        this.skip_button.setFont(new java.awt.Font("Dialog", 1, 18)); // NOI18N
        this.skip_button.setIcon(new javax.swing.ImageIcon(this.getClass().getResource("/images/icons8-trash-can-30.png"))); // NOI18N
        this.skip_button.setText("REMOVE THIS");
        this.skip_button.setDoubleBuffered(true);
        this.skip_button.setEnabled(false);
        this.skip_button.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(final java.awt.event.ActionEvent evt) {
                FolderLinkDialog.this.skip_buttonActionPerformed(evt);
            }
        });

        this.link_detected_label.setFont(new java.awt.Font("Dialog", 1, 24)); // NOI18N
        this.link_detected_label.setIcon(new javax.swing.ImageIcon(this.getClass().getResource("/images/icons8-folder-30.png"))); // NOI18N
        this.link_detected_label.setText("Folder link detected!");
        this.link_detected_label.setDoubleBuffered(true);

        this.dance_button.setBackground(new java.awt.Color(102, 204, 255));
        this.dance_button.setFont(new java.awt.Font("Dialog", 1, 22)); // NOI18N
        this.dance_button.setForeground(new java.awt.Color(255, 255, 255));
        this.dance_button.setText("Loading...");
        this.dance_button.setDoubleBuffered(true);
        this.dance_button.setEnabled(false);
        this.dance_button.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(final java.awt.event.ActionEvent evt) {
                FolderLinkDialog.this.dance_buttonActionPerformed(evt);
            }
        });

        this.folder_link_label.setFont(new java.awt.Font("Dialog", 1, 18)); // NOI18N
        this.folder_link_label.setText("jLabel2");
        this.folder_link_label.setDoubleBuffered(true);

        this.warning_label.setFont(new java.awt.Font("Dialog", 0, 16)); // NOI18N
        this.warning_label.setText("If you DO NOT want to transfer some folder or file you can REMOVE it (to select several items at the same time use CTRL + LMOUSE).");
        this.warning_label.setDoubleBuffered(true);
        this.warning_label.setEnabled(false);

        this.skip_rest_button.setFont(new java.awt.Font("Dialog", 1, 18)); // NOI18N
        this.skip_rest_button.setIcon(new javax.swing.ImageIcon(this.getClass().getResource("/images/icons8-trash-can-30.png"))); // NOI18N
        this.skip_rest_button.setText("REMOVE ALL EXCEPT THIS");
        this.skip_rest_button.setDoubleBuffered(true);
        this.skip_rest_button.setEnabled(false);
        this.skip_rest_button.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(final java.awt.event.ActionEvent evt) {
                FolderLinkDialog.this.skip_rest_buttonActionPerformed(evt);
            }
        });

        this.restore_button.setFont(new java.awt.Font("Dialog", 1, 14)); // NOI18N
        this.restore_button.setIcon(new javax.swing.ImageIcon(this.getClass().getResource("/images/icons8-undelete-30.png"))); // NOI18N
        this.restore_button.setText("Restore folder data");
        this.restore_button.setDoubleBuffered(true);
        this.restore_button.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(final java.awt.event.ActionEvent evt) {
                FolderLinkDialog.this.restore_buttonActionPerformed(evt);
            }
        });

        this.total_space_label.setFont(new java.awt.Font("Dialog", 1, 32)); // NOI18N
        this.total_space_label.setForeground(new java.awt.Color(0, 0, 255));
        this.total_space_label.setText("[---]");
        this.total_space_label.setDoubleBuffered(true);
        this.total_space_label.setEnabled(false);

        final javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this.getContentPane());
        this.getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(this.link_detected_label, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(this.folder_link_label, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addGap(29, 29, 29)
                                                .addComponent(this.restore_button))
                                        .addComponent(this.node_bar, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(this.file_tree_scrollpane, javax.swing.GroupLayout.Alignment.TRAILING)
                                        .addComponent(this.warning_label, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(this.total_space_label, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(this.skip_rest_button)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                .addComponent(this.skip_button)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(this.dance_button)))
                                .addContainerGap())
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(this.link_detected_label)
                                .addGap(8, 8, 8)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(this.folder_link_label)
                                        .addComponent(this.restore_button))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(this.file_tree_scrollpane, javax.swing.GroupLayout.DEFAULT_SIZE, 289, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(this.node_bar, javax.swing.GroupLayout.PREFERRED_SIZE, 14, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(this.total_space_label)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                .addComponent(this.skip_rest_button)
                                                .addComponent(this.skip_button)
                                                .addComponent(this.dance_button))
                                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                                .addComponent(this.warning_label)
                                                .addGap(49, 49, 49)))
                                .addContainerGap())
        );

        this.pack();
    }// </editor-fold>//GEN-END:initComponents

    private void skip_buttonActionPerformed(final java.awt.event.ActionEvent evt) {//GEN-FIRST:event_skip_buttonActionPerformed

        if (deleteSelectedTreeItems(this.file_tree)) {
            this.file_tree.setEnabled(false);
            this.node_bar.setVisible(true);
            this.skip_rest_button.setEnabled(false);
            this.skip_button.setEnabled(false);
            THREAD_POOL.execute(() -> {
                MiscTools.resetTreeFolderSizes(((MegaMutableTreeNode) this.file_tree.getModel().getRoot()));
                MiscTools.calculateTreeFolderSizes(((MegaMutableTreeNode) this.file_tree.getModel().getRoot()));
                this._genDownloadLiks();
                MiscTools.GUIRun(() -> {
                    this.restore_button.setVisible(true);

                    this.file_tree.setEnabled(true);

                    this.file_tree.setModel(new DefaultTreeModel((TreeNode) this.file_tree.getModel().getRoot()));

                    final boolean root_childs = ((TreeNode) this.file_tree.getModel().getRoot()).getChildCount() > 0;

                    this.dance_button.setEnabled(root_childs);

                    this.skip_button.setEnabled(root_childs);

                    this.skip_rest_button.setEnabled(root_childs);
                });
            });

        }

    }//GEN-LAST:event_skip_buttonActionPerformed

    private void dance_buttonActionPerformed(final java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dance_buttonActionPerformed

        this._download = true;

        this.dispose();
    }//GEN-LAST:event_dance_buttonActionPerformed

    private void skip_rest_buttonActionPerformed(final java.awt.event.ActionEvent evt) {//GEN-FIRST:event_skip_rest_buttonActionPerformed

        if (deleteAllExceptSelectedTreeItems(this.file_tree)) {
            this.file_tree.setEnabled(false);
            this.node_bar.setVisible(true);
            this.skip_rest_button.setEnabled(false);
            this.skip_button.setEnabled(false);

            THREAD_POOL.execute(() -> {

                MiscTools.resetTreeFolderSizes(((MegaMutableTreeNode) this.file_tree.getModel().getRoot()));

                MiscTools.calculateTreeFolderSizes(((MegaMutableTreeNode) this.file_tree.getModel().getRoot()));

                this._genDownloadLiks();

                MiscTools.GUIRunAndWait(() -> {
                    this.restore_button.setVisible(true);

                    this.file_tree.setEnabled(true);

                    this.file_tree.setModel(new DefaultTreeModel((TreeNode) this.file_tree.getModel().getRoot()));

                    final boolean root_childs = ((TreeNode) this.file_tree.getModel().getRoot()).getChildCount() > 0;

                    this.dance_button.setEnabled(root_childs);

                    this.skip_button.setEnabled(root_childs);

                    this.skip_rest_button.setEnabled(root_childs);

                });
            });

        }
    }//GEN-LAST:event_skip_rest_buttonActionPerformed

    private void restore_buttonActionPerformed(final java.awt.event.ActionEvent evt) {//GEN-FIRST:event_restore_buttonActionPerformed

        this.restore_button.setText(LabelTranslatorSingleton.getInstance().translate("Restoring data, please wait..."));

        this.file_tree.setEnabled(false);

        this.restore_button.setEnabled(false);

        this.dance_button.setEnabled(false);

        this.node_bar.setVisible(true);

        this.node_bar.setIndeterminate(true);

        this.skip_button.setEnabled(false);

        this.skip_rest_button.setEnabled(false);

        THREAD_POOL.execute(() -> {
            this._loadMegaDirTree();
            this._genDownloadLiks();
            MiscTools.GUIRun(() -> {
                this.restore_button.setVisible(false);
                this.restore_button.setText(LabelTranslatorSingleton.getInstance().translate("Restore folder data"));
                final boolean root_childs = ((TreeNode) this.file_tree.getModel().getRoot()).getChildCount() > 0;

                for (final JComponent c : new JComponent[]{this.restore_button, this.dance_button, this.skip_button, this.skip_rest_button, this.file_tree}) {

                    c.setEnabled(root_childs);
                }

                this.skip_button.setEnabled(root_childs);

                this.skip_rest_button.setEnabled(root_childs);
            });
        });

    }//GEN-LAST:event_restore_buttonActionPerformed

    private void formWindowClosing(final java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowClosing
        // TODO add your handling code here:

        if (this.working && JOptionPane.showConfirmDialog(this, "EXIT?") == 0) {
            this.dispose();
            this.exit = true;
        } else if (!this.working) {
            this.dispose();
            this.exit = true;
        }
    }//GEN-LAST:event_formWindowClosing

    private int _loadMegaDirTree() {

        try {

            this.working = true;

            final HashMap<String, Object> folder_nodes;

            final MegaAPI ma = new MegaAPI();

            String folder_id = findFirstRegex("#F!([^!]+)", this._link, 1);

            String subfolder_id = null;

            if (folder_id.contains("@")) {

                final String[] fids = folder_id.split("@");

                folder_id = fids[0];

                subfolder_id = fids[1];
            }

//            int r = -1;
//
//            if (ma.existsCachedFolderNodes(folder_id)) {
//                r = JOptionPane.showConfirmDialog(this, "Do you want to use FOLDER CACHED VERSION?\n\n(It could speed up the loading of very large folders)", "FOLDER CACHE", JOptionPane.YES_NO_OPTION);
//
//            }

            // Force not use cache version
            final int r = 1;

            if (r == 0) {
                MiscTools.GUIRun(() -> {
                    this.folder_link_label.setText(this._link + " (CACHED VERSION)");
                });
            }

            final String folder_key = findFirstRegex("#F![^!]+!(.+)", this._link, 1);

            folder_nodes = ma.getFolderNodes(folder_id, folder_key, this.node_bar, (r == 0));

            MegaMutableTreeNode root = null;

            final int nodos_totales = folder_nodes.size();

            MiscTools.GUIRun(() -> {
                this.node_bar.setIndeterminate(false);
                this.node_bar.setMaximum(nodos_totales);
                this.node_bar.setValue(0);
            });

            int conta_nodo = 0;

            for (final Object o : folder_nodes.values()) {

                if (this.exit) {
                    return 1;
                }

                conta_nodo++;

                final int c = conta_nodo;

                MiscTools.GUIRun(() -> {
                    this.node_bar.setValue(c);
                });

                final HashMap<String, Object> current_hashmap_node = (HashMap<String, Object>) o;

                MegaMutableTreeNode current_node;

                if (current_hashmap_node.get("jtree_node") == null) {

                    current_node = new MegaMutableTreeNode(current_hashmap_node);

                    current_hashmap_node.put("jtree_node", current_node);

                } else {

                    current_node = (MegaMutableTreeNode) current_hashmap_node.get("jtree_node");
                }

                String parent_id = (String) current_hashmap_node.get("parent");

                final String current_id = (String) current_hashmap_node.get("h");

                boolean ignore_node = false;

                do {

                    if ((subfolder_id == null && folder_nodes.get(parent_id) != null) || (subfolder_id != null && !subfolder_id.equals(current_id) && folder_nodes.get(parent_id) != null)) {

                        final HashMap<String, Object> parent_hashmap_node = (HashMap) folder_nodes.get(parent_id);

                        final MegaMutableTreeNode parent_node;

                        if (parent_hashmap_node.get("jtree_node") == null) {

                            parent_node = new MegaMutableTreeNode(parent_hashmap_node);

                            parent_hashmap_node.put("jtree_node", parent_node);

                        } else {

                            parent_node = (MegaMutableTreeNode) parent_hashmap_node.get("jtree_node");
                        }

                        parent_node.add(current_node);

                        parent_id = (String) parent_hashmap_node.get("parent");

                        current_node = parent_node;

                    } else if (subfolder_id != null && subfolder_id.equals(current_id)) {

                        root = current_node;

                    } else if (subfolder_id != null && folder_nodes.get(parent_id) == null) {

                        ignore_node = true;

                    } else if (subfolder_id == null && folder_nodes.get(parent_id) == null) {

                        root = current_node;
                    }

                } while (current_node != root && !ignore_node);
            }

            MiscTools.GUIRun(() -> {

                this.node_bar.setIndeterminate(true);
            });

            if (root != null) {
                MiscTools.sortTree(root);

                MiscTools.calculateTreeFolderSizes(root);
            }

            if (root == null) {
                LOG.log(SEVERE, null, "MEGA FOLDER ERROR (EMPTY?)");

                this._mega_error = 2;

            } else {

                root.setParent(null);

                final JTree ftree = this.file_tree;

                final MegaMutableTreeNode roott = root;

                MiscTools.GUIRunAndWait(() -> {

                    this.node_bar.setIndeterminate(true);

                    ftree.setModel(new DefaultTreeModel(roott));

                    ftree.setRootVisible(roott != null ? roott.getChildCount() > 0 : false);

                    ftree.setEnabled(true);
                });

            }

        } catch (final MegaAPIException mex) {

            LOG.log(SEVERE, null, mex);

            this._mega_error = mex.getCode();

        } catch (final Exception ex) {

            LOG.log(SEVERE, null, ex);

            this._mega_error = 1;
        }

        this.working = false;

        return 0;

    }

    public void generateDownloadLinks() {
        this._loadMegaDirTree();
        this.working = true;

        this._download_links.clear();

        final MegaMutableTreeNode root = (MegaMutableTreeNode) this.file_tree.getModel().getRoot();

        final Enumeration files_tree = root.depthFirstEnumeration();

        this.total_space_label.setText("[---]");


        String folder_id = findFirstRegex("#F!([^!]+)", this._link, 1);

        if (folder_id.contains("@")) {

            final String[] fids = folder_id.split("@");

            folder_id = fids[0];
        }

        this._total_space = 0L;

        while (files_tree.hasMoreElements()) {

            final MegaMutableTreeNode node = (MegaMutableTreeNode) files_tree.nextElement();

            if (node.isLeaf() && node != root && ((HashMap<String, Object>) node.getUserObject()).get("size") != null) {

                String path = "";

                final Object[] object_path = node.getUserObjectPath();

                for (final Object p : object_path) {

                    path += File.separator + ((Map<String, Object>) p).get("name");
                }

                path = path.replaceAll("^/+", "").replaceAll("^\\+", "").trim();

                final String url = "https://mega.nz/#N!" + ((Map<String, Object>) node.getUserObject()).get("h") + "!" + ((Map<String, Object>) node.getUserObject()).get("key") + "###n=" + folder_id;

                final HashMap<String, Object> download_link = new HashMap<>();

                download_link.put("url", url);

                download_link.put("filename", cleanFilePath(path));

                download_link.put("filekey", ((Map<String, Object>) node.getUserObject()).get("key"));

                download_link.put("filesize", ((Map<String, Object>) node.getUserObject()).get("size"));

                this._total_space += (long) download_link.get("filesize");

                this._download_links.add(download_link);
            } else if (node.isLeaf() && node != root) {
                String path = "";

                final Object[] object_path = node.getUserObjectPath();

                for (final Object p : object_path) {

                    path += File.separator + ((Map<String, Object>) p).get("name");
                }

                path = path.replaceAll("^/+", "").replaceAll("^\\+", "").trim();

                final HashMap<String, Object> download_link = new HashMap<>();

                download_link.put("url", "*");

                download_link.put("filename", cleanFilePath(path));

                download_link.put("type", ((HashMap<String, Object>) node.getUserObject()).get("type"));

                this._download_links.add(download_link);
            }
        }
        this.dance_button.doClick();

    }


    private void _genDownloadLiks() {

        MiscTools.GUIRun(() -> {
            this.working = true;

            this._download_links.clear();

            final MegaMutableTreeNode root = (MegaMutableTreeNode) this.file_tree.getModel().getRoot();

            final Enumeration files_tree = root.depthFirstEnumeration();

            this.total_space_label.setText("[---]");

            THREAD_POOL.execute(() -> {

                String folder_id = findFirstRegex("#F!([^!]+)", this._link, 1);

                if (folder_id.contains("@")) {

                    final String[] fids = folder_id.split("@");

                    folder_id = fids[0];
                }

                this._total_space = 0L;

                while (files_tree.hasMoreElements()) {

                    final MegaMutableTreeNode node = (MegaMutableTreeNode) files_tree.nextElement();

                    if (node.isLeaf() && node != root && ((HashMap<String, Object>) node.getUserObject()).get("size") != null) {

                        String path = "";

                        final Object[] object_path = node.getUserObjectPath();

                        for (final Object p : object_path) {

                            path += File.separator + ((Map<String, Object>) p).get("name");
                        }

                        path = path.replaceAll("^/+", "").replaceAll("^\\+", "").trim();

                        final String url = "https://mega.nz/#N!" + ((Map<String, Object>) node.getUserObject()).get("h") + "!" + ((Map<String, Object>) node.getUserObject()).get("key") + "###n=" + folder_id;

                        final HashMap<String, Object> download_link = new HashMap<>();

                        download_link.put("url", url);

                        download_link.put("filename", cleanFilePath(path));

                        download_link.put("filekey", ((Map<String, Object>) node.getUserObject()).get("key"));

                        download_link.put("filesize", ((Map<String, Object>) node.getUserObject()).get("size"));

                        this._total_space += (long) download_link.get("filesize");

                        this._download_links.add(download_link);
                    } else if (node.isLeaf() && node != root) {
                        String path = "";

                        final Object[] object_path = node.getUserObjectPath();

                        for (final Object p : object_path) {

                            path += File.separator + ((Map<String, Object>) p).get("name");
                        }

                        path = path.replaceAll("^/+", "").replaceAll("^\\+", "").trim();

                        final HashMap<String, Object> download_link = new HashMap<>();

                        download_link.put("url", "*");

                        download_link.put("filename", cleanFilePath(path));

                        download_link.put("type", ((HashMap<String, Object>) node.getUserObject()).get("type"));

                        this._download_links.add(download_link);
                    }
                }

                MiscTools.GUIRunAndWait(() -> {

                    this.total_space_label.setText("[" + formatBytes(this._total_space) + "]");

                    for (final JComponent c : new JComponent[]{this.dance_button, this.warning_label, this.skip_button, this.skip_rest_button, this.total_space_label}) {

                        c.setEnabled(root.getChildCount() > 0);
                    }

                    this.node_bar.setVisible(false);

                    this.working = false;
                });

            });
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton dance_button;
    private final javax.swing.JTree file_tree = new javax.swing.JTree();
    private javax.swing.JScrollPane file_tree_scrollpane;
    private javax.swing.JLabel folder_link_label;
    private javax.swing.JLabel link_detected_label;
    private javax.swing.JProgressBar node_bar;
    private javax.swing.JButton restore_button;
    private javax.swing.JButton skip_button;
    private javax.swing.JButton skip_rest_button;
    private javax.swing.JLabel total_space_label;
    private javax.swing.JLabel warning_label;
    // End of variables declaration//GEN-END:variables
    private static final Logger LOG = Logger.getLogger(FolderLinkDialog.class.getName());
}
