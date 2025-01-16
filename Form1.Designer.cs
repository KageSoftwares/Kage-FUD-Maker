using System.Drawing;
using System.Windows.Forms;
using KageFudMaker.Properties;

namespace RunPEGenerator
{
    partial class Form1
    {
        private System.ComponentModel.IContainer components = null;
        private System.Windows.Forms.RadioButton Type1RadioButton;
        private System.Windows.Forms.RadioButton Type2RadioButton;
        private System.Windows.Forms.RadioButton Type3RadioButton;
        private System.Windows.Forms.RadioButton Type4RadioButton;
        private System.Windows.Forms.RadioButton Type5RadioButton;
        private System.Windows.Forms.RadioButton Type6RadioButton;
        private System.Windows.Forms.RadioButton Type7RadioButton;
        private System.Windows.Forms.RadioButton Type41RadioButton;
        private System.Windows.Forms.RadioButton Type42RadioButton;
        private System.Windows.Forms.Button GenerateButton;
        private System.Windows.Forms.TextBox OutputTextBox;
        private System.Windows.Forms.Button SaveButton;
        private System.Windows.Forms.Button ClearButton; 
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.TabControl tabControl;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TabPage tabPage2;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.tabControl = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.Type1RadioButton = new System.Windows.Forms.RadioButton();
            this.Type2RadioButton = new System.Windows.Forms.RadioButton();
            this.Type3RadioButton = new System.Windows.Forms.RadioButton();
            this.Type4RadioButton = new System.Windows.Forms.RadioButton();
            this.Type5RadioButton = new System.Windows.Forms.RadioButton();
            this.Type6RadioButton = new System.Windows.Forms.RadioButton();
            this.Type7RadioButton = new System.Windows.Forms.RadioButton();
            this.Type41RadioButton = new System.Windows.Forms.RadioButton();
            this.Type42RadioButton = new System.Windows.Forms.RadioButton();
            this.GenerateButton = new System.Windows.Forms.Button();
            this.OutputTextBox = new System.Windows.Forms.TextBox();
            this.SaveButton = new System.Windows.Forms.Button();
            this.ClearButton = new System.Windows.Forms.Button();
            this.button1 = new System.Windows.Forms.Button();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.tabControl.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.SuspendLayout();
            // 
            // tabControl
            // 
            this.tabControl.Controls.Add(this.tabPage1);
            this.tabControl.Controls.Add(this.tabPage2);
            this.tabControl.Location = new System.Drawing.Point(12, 12);
            this.tabControl.Name = "tabControl";
            this.tabControl.SelectedIndex = 0;
            this.tabControl.Size = new System.Drawing.Size(460, 300);
            this.tabControl.TabIndex = 0;
            // 
            // tabPage1
            // 
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(452, 274);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Tab 1";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // tabPage2
            // 
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(452, 274);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Tab 2";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // Type1RadioButton
            // 
            this.Type1RadioButton.AutoSize = true;
            this.Type1RadioButton.ForeColor = System.Drawing.SystemColors.ButtonHighlight;
            this.Type1RadioButton.Location = new System.Drawing.Point(12, 13);
            this.Type1RadioButton.Margin = new System.Windows.Forms.Padding(9);
            this.Type1RadioButton.Name = "Type1RadioButton";
            this.Type1RadioButton.Size = new System.Drawing.Size(68, 17);
            this.Type1RadioButton.TabIndex = 0;
            this.Type1RadioButton.TabStop = true;
            this.Type1RadioButton.Text = "RunPE 1";
            this.Type1RadioButton.UseVisualStyleBackColor = true;
            // 
            // Type2RadioButton
            // 
            this.Type2RadioButton.AutoSize = true;
            this.Type2RadioButton.ForeColor = System.Drawing.SystemColors.ButtonHighlight;
            this.Type2RadioButton.Location = new System.Drawing.Point(12, 36);
            this.Type2RadioButton.Margin = new System.Windows.Forms.Padding(9);
            this.Type2RadioButton.Name = "Type2RadioButton";
            this.Type2RadioButton.Size = new System.Drawing.Size(68, 17);
            this.Type2RadioButton.TabIndex = 1;
            this.Type2RadioButton.TabStop = true;
            this.Type2RadioButton.Text = "RunPE 2";
            this.Type2RadioButton.UseVisualStyleBackColor = true;
            // 
            // Type3RadioButton
            // 
            this.Type3RadioButton.AutoSize = true;
            this.Type3RadioButton.ForeColor = System.Drawing.SystemColors.ButtonHighlight;
            this.Type3RadioButton.Location = new System.Drawing.Point(12, 59);
            this.Type3RadioButton.Margin = new System.Windows.Forms.Padding(9);
            this.Type3RadioButton.Name = "Type3RadioButton";
            this.Type3RadioButton.Size = new System.Drawing.Size(68, 17);
            this.Type3RadioButton.TabIndex = 2;
            this.Type3RadioButton.TabStop = true;
            this.Type3RadioButton.Text = "RunPE 3";
            this.Type3RadioButton.UseVisualStyleBackColor = true;
            // 
            // Type4RadioButton
            // 
            this.Type4RadioButton.AutoSize = true;
            this.Type4RadioButton.ForeColor = System.Drawing.SystemColors.ButtonHighlight;
            this.Type4RadioButton.Location = new System.Drawing.Point(252, 13);
            this.Type4RadioButton.Margin = new System.Windows.Forms.Padding(9);
            this.Type4RadioButton.Name = "Type4RadioButton";
            this.Type4RadioButton.Size = new System.Drawing.Size(97, 17);
            this.Type4RadioButton.TabIndex = 3;
            this.Type4RadioButton.TabStop = true;
            this.Type4RadioButton.Text = "AMSI Bypass 1";
            this.Type4RadioButton.UseVisualStyleBackColor = true;
            // 
            // Type5RadioButton
            // 
            this.Type5RadioButton.AutoSize = true;
            this.Type5RadioButton.ForeColor = System.Drawing.SystemColors.ButtonHighlight;
            this.Type5RadioButton.Location = new System.Drawing.Point(96, 36);
            this.Type5RadioButton.Margin = new System.Windows.Forms.Padding(9);
            this.Type5RadioButton.Name = "Type5RadioButton";
            this.Type5RadioButton.Size = new System.Drawing.Size(138, 17);
            this.Type5RadioButton.TabIndex = 6;
            this.Type5RadioButton.TabStop = true;
            this.Type5RadioButton.Text = "x0r Şifreleme / Encrypte";
            this.Type5RadioButton.UseVisualStyleBackColor = true;
            // 
            // Type6RadioButton
            // 
            this.Type6RadioButton.AutoSize = true;
            this.Type6RadioButton.ForeColor = System.Drawing.SystemColors.ButtonHighlight;
            this.Type6RadioButton.Location = new System.Drawing.Point(98, 13);
            this.Type6RadioButton.Margin = new System.Windows.Forms.Padding(9);
            this.Type6RadioButton.Name = "Type6RadioButton";
            this.Type6RadioButton.Size = new System.Drawing.Size(145, 17);
            this.Type6RadioButton.TabIndex = 7;
            this.Type6RadioButton.TabStop = true;
            this.Type6RadioButton.Text = "RC4 Şifreleme / Encrypte";
            this.Type6RadioButton.UseVisualStyleBackColor = true;
            // 
            // Type7RadioButton
            // 
            this.Type7RadioButton.AutoSize = true;
            this.Type7RadioButton.ForeColor = System.Drawing.SystemColors.ButtonHighlight;
            this.Type7RadioButton.Location = new System.Drawing.Point(98, 59);
            this.Type7RadioButton.Margin = new System.Windows.Forms.Padding(9);
            this.Type7RadioButton.Name = "Type7RadioButton";
            this.Type7RadioButton.Size = new System.Drawing.Size(145, 17);
            this.Type7RadioButton.TabIndex = 8;
            this.Type7RadioButton.TabStop = true;
            this.Type7RadioButton.Text = "AES Şifreleme / Encrypte";
            this.Type7RadioButton.UseVisualStyleBackColor = true;
            // 
            // Type41RadioButton
            // 
            this.Type41RadioButton.AutoSize = true;
            this.Type41RadioButton.ForeColor = System.Drawing.SystemColors.ButtonHighlight;
            this.Type41RadioButton.Location = new System.Drawing.Point(252, 36);
            this.Type41RadioButton.Margin = new System.Windows.Forms.Padding(9);
            this.Type41RadioButton.Name = "Type41RadioButton";
            this.Type41RadioButton.Size = new System.Drawing.Size(97, 17);
            this.Type41RadioButton.TabIndex = 4;
            this.Type41RadioButton.TabStop = true;
            this.Type41RadioButton.Text = "AMSI Bypass 2";
            this.Type41RadioButton.UseVisualStyleBackColor = true;
            // 
            // Type42RadioButton
            // 
            this.Type42RadioButton.AutoSize = true;
            this.Type42RadioButton.ForeColor = System.Drawing.SystemColors.ButtonHighlight;
            this.Type42RadioButton.Location = new System.Drawing.Point(252, 59);
            this.Type42RadioButton.Margin = new System.Windows.Forms.Padding(9);
            this.Type42RadioButton.Name = "Type42RadioButton";
            this.Type42RadioButton.Size = new System.Drawing.Size(97, 17);
            this.Type42RadioButton.TabIndex = 5;
            this.Type42RadioButton.TabStop = true;
            this.Type42RadioButton.Text = "AMSI Bypass 3";
            this.Type42RadioButton.UseVisualStyleBackColor = true;
            // 
            // GenerateButton
            // 
            this.GenerateButton.Font = new System.Drawing.Font("Verdana", 8.25F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.GenerateButton.Location = new System.Drawing.Point(12, 88);
            this.GenerateButton.Name = "GenerateButton";
            this.GenerateButton.Size = new System.Drawing.Size(715, 28);
            this.GenerateButton.TabIndex = 9;
            this.GenerateButton.Text = "Kod Üret / Generate";
            this.GenerateButton.UseVisualStyleBackColor = true;
            this.GenerateButton.Click += new System.EventHandler(this.GenerateButton_Click);
            // 
            // OutputTextBox
            // 
            this.OutputTextBox.BackColor = System.Drawing.SystemColors.InactiveCaptionText;
            this.OutputTextBox.ForeColor = System.Drawing.SystemColors.Window;
            this.OutputTextBox.Location = new System.Drawing.Point(12, 122);
            this.OutputTextBox.Multiline = true;
            this.OutputTextBox.Name = "OutputTextBox";
            this.OutputTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.OutputTextBox.Size = new System.Drawing.Size(715, 448);
            this.OutputTextBox.TabIndex = 10;
            // 
            // SaveButton
            // 
            this.SaveButton.Font = new System.Drawing.Font("Verdana", 8.25F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.SaveButton.Location = new System.Drawing.Point(377, 13);
            this.SaveButton.Name = "SaveButton";
            this.SaveButton.Size = new System.Drawing.Size(350, 28);
            this.SaveButton.TabIndex = 11;
            this.SaveButton.Text = "Kaydet / Save";
            this.SaveButton.UseVisualStyleBackColor = true;
            this.SaveButton.Click += new System.EventHandler(this.SaveButton_Click);
            // 
            // ClearButton
            // 
            this.ClearButton.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.ClearButton.Font = new System.Drawing.Font("Verdana", 8.25F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.ClearButton.Location = new System.Drawing.Point(377, 47);
            this.ClearButton.Name = "ClearButton";
            this.ClearButton.Size = new System.Drawing.Size(350, 29);
            this.ClearButton.TabIndex = 12;
            this.ClearButton.Text = "Temizle / Clean";
            this.ClearButton.UseVisualStyleBackColor = true;
            this.ClearButton.Click += new System.EventHandler(this.ClearButton_Click);
            // 
            // button1
            // 
            this.button1.Font = new System.Drawing.Font("Verdana", 8.25F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.button1.Location = new System.Drawing.Point(12, 576);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(715, 29);
            this.button1.TabIndex = 13;
            this.button1.Text = "Kopyala";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.CopyButton_Click);
            // 
            // pictureBox1
            // 
            this.pictureBox1.Image = ((System.Drawing.Image)(resources.GetObject("pictureBox1.Image")));
            this.pictureBox1.Location = new System.Drawing.Point(743, 13);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(654, 592);
            this.pictureBox1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.pictureBox1.TabIndex = 14;
            this.pictureBox1.TabStop = false;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.SystemColors.ActiveCaptionText;
            this.ClientSize = new System.Drawing.Size(1409, 617);
            this.Controls.Add(this.pictureBox1);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.ClearButton);
            this.Controls.Add(this.SaveButton);
            this.Controls.Add(this.OutputTextBox);
            this.Controls.Add(this.GenerateButton);
            this.Controls.Add(this.Type7RadioButton);
            this.Controls.Add(this.Type6RadioButton);
            this.Controls.Add(this.Type5RadioButton);
            this.Controls.Add(this.Type42RadioButton);
            this.Controls.Add(this.Type41RadioButton);
            this.Controls.Add(this.Type4RadioButton);
            this.Controls.Add(this.Type3RadioButton);
            this.Controls.Add(this.Type2RadioButton);
            this.Controls.Add(this.Type1RadioButton);
            this.Name = "Form1";
            this.ShowIcon = false;
            this.Text = "Kage | FUD Maker ";
            this.tabControl.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        private PictureBox pictureBox1;
    }
}
