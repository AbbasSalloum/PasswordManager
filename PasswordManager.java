import java.awt.*;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.security.SecureRandom;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEPar




class SplashScreen{
    JFrame frame;
    JLabel image = new JLabel(ImageIcon("key-lock.png"));
    JLabel text = new JLabel("PASSWORD & NOTES MANAGER");
    JProgressBar progressBar = new JProgressBar;
    JLabel message = new JLabel();

    SplashScreen(){
        createGUI();
        addImage();
        addText();
        addProgressBar();
        runningPBar();
    }

    public void createGUI(){
        frame = new JFrame(); // to create a frame
        frame.getContentPane().setLayout(null); // to set the layout of the frame
        frame.setUndecorated(true);
        frame.setSize(400,400); // set size for the frame
        frame.setLocationRelativeTo(null);
        frame.getContentPane().setBackground(new Color(0XFF8787));// to set the background color of the frame
        frame.setVisible(true);

    }
    public void addImage(){
        image.setSize(400,200);
        frame.add(image);
    }

    public void addText(){
        text.setFont(new Font("MV Boli", Font.BOLD,20));
        text.setBounds(30,200,400,30);
        text.setForeground(Color.black);
        frame.add(text);
    }

       public void addProgressBar(){
        progressBar.setBounds(100,280,200,30); // to set the size of the progress bar
        progressBar.setBorderPainted(true);
        progressBar.setStringPainted(true);
        progressBar.setBackground(Color.black);
        progressBar.setForeground(new Color(0X38E54D));
        progressBar.setValue(0);
        frame.add(progressBar);
    }

       public void runningPBar(){
        int i=0;//Creating an integer variable and initializing it to 0
        while( i<=100)
        {
            try{
                Thread.sleep(40);   //Pausing execution for 50 milliseconds
                progressBar.setValue(i);    //Setting value of Progress Bar
                i++;
                if(i==100)
                    frame.dispose();
            }catch(Exception e){
                e.printStackTrace();
            }
        }
  


}