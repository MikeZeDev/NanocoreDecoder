using System;
using System.Windows.Forms;

namespace NanocoreDecoder
{
    public partial class Form1 : Form
    {



        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            AllowDrop = true;
  
        }

        private void Form1_DragEnter(object sender, DragEventArgs e)
        {
             if(e.Data.GetDataPresent(DataFormats.FileDrop))
             {
                e.Effect = DragDropEffects.Copy;

             }
     
        }

        private void Form1_DragDrop(object sender, DragEventArgs e)
        {
            label1.Visible = false;
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            foreach (string filePath in files)
            {
                propertyGrid1.SelectedObject = null;

                if (Decoders.Common.Decoder(filePath))
                {
                    propertyGrid1.SelectedObject = new DictionaryPropertyGridAdapter(NanocoreDecoder.Decoders.Common.dictionary_1);

                }

                break;
            }
        }

   
    }
}
