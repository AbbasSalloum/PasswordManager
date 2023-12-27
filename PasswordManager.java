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

class HashtablePassword implements hashTableMap{
    private final int useProbe;    //0 = Linear Probing, 1 = Quadratic Probing
    private Entry[] entries;       //The array of entries
    private final float loadFactor;     //The load factor
    private int size, used;         //used acquires space for NIL
    private final Entry NIL = new Entry(null, null); //Deleted entries

    private static class Entry{
        Object key, value;
        Entry(Object k, Object v){
            key = k;    value = v;
        }
    }
    public HashtablePassword(int capacity, float loadFactor, int useProbe){
        entries = new Entry[capacity];
        this.loadFactor = loadFactor;
        this.useProbe = useProbe;
    }


    //Complementary functions
    public int hash(Object key){
        return (key.hashCode() & 0x7FFFFFFF) % entries.length;
    }

    private int nextProbe(int h, int i){
        return (h+i) % entries.length;  //Linear Probing
    }

    private void rehash(){ 
        Entry[] oldEntries = entries;
        entries = new Entry[2*entries.length+1];
        for (Entry entry : oldEntries) {
            if (entry == NIL || entry == null) continue;
            int h = hash(entry.key);
            for (int x = 0; x < entries.length; x++) {
                int j = nextProbe(h, x);
                if (entries[j] == null) {
                    entries[j] = entry;
                    break;
                }
            }
            used = size;
        }
    }

    @Override
    public int add_Acc(Object Account, Object passwd) {
        if(used > (loadFactor*entries.length))rehash();
        int h = hash(Account);
        for (int i = 0; i < entries.length; i++){
            int j = (h+i) % entries.length;
            Entry entry = entries[j];
            if(entry==null){
                entries[j]= new Entry(Account, passwd);
                ++size;
                ++used;
                return h;
            }
            if(entry == NIL)continue;
            if(entry.key.equals(Account)){
                Object oldValue = entry.value;
                entries[j].value = passwd;
                return (int) oldValue;
            }
        }
        return h;
    }

    @Override
    public Object get_Acc(Object Account) {
        int h = hash(Account);
        for(int i = 0; i < entries.length; i++){
            int j = nextProbe(h , i);
            Entry entry = entries[j];
            if(entry == null)break;
            if(entry == NIL)continue;
            if(entry.key.equals(Account)) return entry.value;
        }
        return null;
    }

    @Override
    public Object remove_Acc(Object Account) {
        int h = hash(Account);
        for(int i = 0; i < entries.length; i++){
            int j = nextProbe(h,i);
            Entry entry = entries[j];
            if(entry == NIL)continue;
            if(entry.key.equals(Account)){
                Object Value = entry.value;
                entries[j] = NIL;
                size--;
                return Value;
            }
        }
        return null;
    }
}

class CryptoUtil 
{

    Cipher ecipher;
    Cipher dcipher;
    // 8-byte Salt
    byte[] salt = {
        (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
        (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03
    };
    // Iteration count
    int iterationCount = 19;

    public CryptoUtil() {

    }

    /**
     *
     * @param secretKey Key used to encrypt data
     * @param plainText Text input to be encrypted
     * @return Returns encrypted text
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.io.UnsupportedEncodingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     *
     */
    public String encrypt(String secretKey, String plainText)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            UnsupportedEncodingException,
            IllegalBlockSizeException,
            BadPaddingException {
        //Key generation for enc and desc
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
        // Prepare the parameter to the ciphers
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);

        //Enc process
        ecipher = Cipher.getInstance(key.getAlgorithm());
        ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        String charSet = "UTF-8";
        byte[] in = plainText.getBytes(charSet);
        byte[] out = ecipher.doFinal(in);
        String encStr = new String(Base64.getEncoder().encode(out));
        return encStr;
    }

    /**
     * @param secretKey Key used to decrypt data
     * @param encryptedText encrypted text input to decrypt
     * @return Returns plain text after decryption
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.io.UnsupportedEncodingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public String decrypt(String secretKey, String encryptedText)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            UnsupportedEncodingException,
            IllegalBlockSizeException,
            BadPaddingException,
            IOException {
        //Key generation for enc and desc
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
        // Prepare the parameter to the ciphers
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
        //Decryption process; same key will be used for decr
        dcipher = Cipher.getInstance(key.getAlgorithm());
        dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        byte[] enc = Base64.getDecoder().decode(encryptedText);
        byte[] utf8 = dcipher.doFinal(enc);
        String charSet = "UTF-8";
        String plainStr = new String(utf8, charSet);
        return plainStr;
    }    
   
}

class PasswordGenerator{
    private static final SecureRandom random = new SecureRandom();
    private static final String caps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String small_caps = "abcdefhghijklmnopqrstuvwxyz";
    private static final String Numeric = "123456789";
    private static final String special_char = "~!@#$%^&*(_+{[?=><]})";
    private static final String dic = caps + small_caps + Numeric + special_char;

    public String generatePassword(int len){
        StringBuilder password = new StringBuilder();
        for(int i = 0; i < len ; i++){
            int index = random.nextInt(dic.length);
            password.append(dic.charAt(index));
        }
        return password.toString();
    }

}

interface hashTableMap{
    Object get_Acc(Object Account);
    int add_Acc(Object Account, Object passwd);
    Object remove_Acc(Object Account);
}

class PasswordManager implements ActionListener{
    HashtablePassword data = new HashtablePassword(15,0.5F,0);

    JFrame frame;
    
}
