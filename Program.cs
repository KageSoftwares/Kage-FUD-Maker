using System;
using System.Windows.Forms;

namespace RunPEGenerator
{
    static class Program
    {
        // Uygulamanın başlangıç noktası
        [STAThread]
        static void Main()
        {
            // Uygulamanın görsel stilini ayarlayın (isteğe bağlı)
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Form1'i başlatın
            Application.Run(new Form1());
        }
    }
}
