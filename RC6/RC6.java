/*
 * 		Name : 		Tanmay Kale
 * 		Subject :	CS458 Computer Security
 * 		Project 1.
 * 		Aim : To implement RC6 algorithm.
 * */

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
public class assignment1
{

		private static BufferedReader br;
		static FileReader in;
		static int r = 20, w=32;
		static int wordLength = (2*r)+4;
		static int S[];
		static int A,B,C,D;
		static int P32 =  0xB7E15163;
		static int Q32 =  0x9E3779B9;
		static int t = (2*r) + 4;
		static int u = w/8; 
		static String plainText, cipherText;
		static String userKey_temp;
		static int userKey[];
		static int num;
		static int flag = 0;
		static int Final_cipherText[];
		static int Final_plainText[];
		
		//Left shit the value by shift_valIn bits
		static int shiftLeft(int varIn, int shift_valIn)
		{
			return (varIn << shift_valIn) | (varIn >>> (32-shift_valIn));

		}
		//Right shit the value by shift_valIn bits
		static int shiftRight(int varIn, int shift_valIn)
		{
			return (varIn >>> shift_valIn) | (varIn << (32-shift_valIn));
		}

		// Reverse the final cipher Text
		public static int reverseBytes(int bits)
		{ 
			return Integer.reverseBytes(bits);
		}
		
		void encryption()
		{			
			A = reverseBytes(A);
			B = reverseBytes(B);
			C = reverseBytes(C);
			D = reverseBytes(D);
			//System.out.print(Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");			
			
			B = B + S[0];
			D = D + S[1];
			
			for(int i=1; i<=r; i++)
			{
				t = shiftLeft((B *(2 * B + 1)), 5 );
				u = shiftLeft((D *(2 * D + 1)), 5 );
				A = shiftLeft((A ^ t), u ) + S[2 * i];
				C = shiftLeft((C ^ u), t ) + S[2 * i + 1];
				t = A; A=B; B=C; C=D; D=t;
			}
			
			A = A + S[2*r+2];
			C = C + S[2*r+3];	
			
			//System.out.print(Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");
			
			A = reverseBytes(A);
			B = reverseBytes(B);
			C = reverseBytes(C);
			D = reverseBytes(D);
			
			System.out.print("Encryption Text : "+Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");			
			Final_cipherText = new int[] { A, B, C, D }; 
			//return  
		}

		void decryption()
		{
			A = reverseBytes(A);
			B = reverseBytes(B);
			C = reverseBytes(C);
			D = reverseBytes(D);
//			System.out.print("BEFORE DECRYPTION : "+ Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");
			
			C = C - S[2*r+3];
			A = A - S[2*r+2];
			for(int i=2*r+2;i>2;)
			{
				t = D; D = C; C = B; B = A; A = t;
				u = shiftLeft( D*(2*D+1), 5 );
				t = shiftLeft( B*(2*B+1), 5 );
				C = shiftRight( C-S[--i], t ) ^ u;
				A = shiftRight( A-S[--i], u ) ^ t;
			}
			
			D = D - S[1];
			B = B - S[0]; 
//			System.out.print("after Decryption: "+Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");			
			
			A = reverseBytes(A);
			B = reverseBytes(B);
			C = reverseBytes(C);
			D = reverseBytes(D);
			System.out.print("After Decryption: "+Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");			
			Final_plainText = new int[] { A, B, C, D };
		}
		public static int[] KeySchedule(int userKey[], int r, int b){
		
			int u = w/8; 		// number of bytes/word
			int c = b/u; 		// Words
			int i = 0;
			int v;
			
			int [] L = new int[c];
			
			for(i = 0; i<c; i++)
			{
				L[i] = 0x00;
			}
		
			int counter;
			for (i = 0, counter = 0; i < c; i++)
			{
				L[i] = ((userKey[counter++] )) | ((userKey[counter++] ) << 8)| ((userKey[counter++] ) << 16) | ((userKey[counter++] ) << 24);
			}
			
			S = new int[t];
			
			S[0] = P32;
			for(i=1; i<t; i++)
			{
				S[i] = S[i-1] + Q32; 
			}
			
			A = 0;
			B = 0;
			
			int j = 0;
			i=0;
			
			v = 3 * Math.max(c, (2*r+4) );
			for (int s = 0; s < v; s++)
			{
				A = S[i] = shiftLeft((S[i] + A + B), 3);
				B = L[j] = shiftLeft(L[j] + A + B, A + B);
				i = (i + 1) % (2*r+4);
				j = (j + 1) % c;
			}

			return S;
	}
		// READ THE FILE AND FIND OUT THE MODE OF OPERATION I.E TO ENCRYPT/DECRYPT
	public static int readtype(String filenameIn) throws IOException
	{
		int typeID = 0;
		in = new FileReader(filenameIn);
		br = new BufferedReader(in);
		String type = br.readLine();
		System.out.println("Operation to Do: " + type);
		
		if(type.equals("Encryption") || type.equals("encryption"))
		{
			// Reading the plain text from the input file.
			String plainTextLine = br.readLine();
			plainText = plainTextLine.replace("plaintext: ", "");
			plainText = plainText.replaceAll("\\s+","");
			System.out.println("PlainText :\t" + plainText);
			
			// Reading the userkey text from the input file.			
			String userKeyLine = br.readLine();
			userKey_temp = userKeyLine.replace("userkey: ", "");
			userKey_temp = userKey_temp.replaceAll("\\s+","");
			System.out.println("userKey :\t" + userKey_temp);
			
			// Finding the length of the plain text.
			num = userKey_temp.length()/2;
//			System.out.println("userKey length : ");
			typeID = 1;
			userKey = new int[num];
			conToInt(userKey_temp,userKey, num);
			flag=1;
			
		}
		if(type.equals("Decryption") || type.equals("decryption"))
		{
			// Reading the cipherText from the input file.			
			String cipherTextLine = br.readLine();
			cipherText = cipherTextLine.replace("ciphertext: ", "");
			cipherText = cipherText.replaceAll("\\s+","");
			System.out.println("cipherText :\t" + cipherText);

			// Reading the userkey text from the input file.			
			String userKeyLine = br.readLine();
			userKey_temp = userKeyLine.replace("userkey: ", "");
			userKey_temp = userKey_temp.replaceAll("\\s+","");
			System.out.println("userKey :\t" + userKey_temp);
			
			//Getting the length cipher text. 
			num = cipherText.length()/2;
//			System.out.println("cipherText length : " + num);
			typeID = 2;
			userKey = new int[num];
			conToInt(userKey_temp,userKey, num);
			flag =2;
		}
		return typeID;
	}
	//To convert the 32 bit key and store it in an integer[].
	static void conToInt(String key, int[] userKey, int num)
	{
		for(int i=0; i < num; i++)
		{
			userKey[i] = Integer.parseInt(key.charAt(i*2) + "" , 16 );
			userKey[i] = shiftLeft( userKey[i], 4);
			userKey[i] = userKey[i] + Integer.parseInt( key.charAt(i*2+1) + "", 16);
		}
	}
	// Main of the program
	public static void main(String[] args) throws IOException
	{
		String filename;
		filename = args[0];
		int type_ID = 0;
		assignment1 assign1_Obj = new assignment1();
		System.out.println("Filename : " + filename +"\n");
		
		//Read the file and find out if the file given text is ciphertext or plaintext and initialize the arrays
		try {
			type_ID = readtype(filename);
		} catch (IOException e) {
			System.out.println("FILE NOT FOUND.");
			e.printStackTrace();
		}
		int b = (userKey_temp.length()/2);
		int K[] = userKey;
		
		S = KeySchedule(K,r, b);	
		
		int num;
		int [] inputText = null;
		
		//This divides given String into 1 byte Integer
		
		if(flag ==1 )
		{
			num = plainText.length()/2;
			inputText = new int[num];
			
			for(int i=0;i<num;i++)
			{
				inputText[i] = Integer.parseInt(plainText.charAt(i*2) + "" , 16 );
				inputText[i] = shiftLeft(inputText[i], 4);	
				inputText[i] = inputText[i] + Integer.parseInt(plainText.charAt(i*2+1) + "", 16);
				//System.out.println("Final_plainTextInput : "+inputText[i]);
			}
		}
		if(flag == 2)
		{
			num = cipherText.length()/2;
			inputText = new int[num];
			
			for(int i=0;i<num;i++)
			{
				inputText[i] = Integer.parseInt(cipherText.charAt(i*2) + "" , 16 );
				inputText[i] = shiftLeft(inputText[i], 4);	
				inputText[i] = inputText[i] + Integer.parseInt(cipherText.charAt(i*2+1) + "", 16);
				//System.out.println("Final_cipherTextInput : "+inputText[i]);
			}
		}
		//Initialize all the ABCD registers with hexadeciaml 0 value.
		A = B = C = D = 0x00;

		int length = inputText.length/4;
			
		for(int i=0;i<length;i++)
		{
			A = shiftLeft(A, 8) + inputText[i];
		}		
		
		for(int i = length; i<length*2;i++)
		{
			B = shiftLeft(B, 8) + inputText[i];
		}		

		for(int i=length*2 ;i<length*3;i++)
		{
			C = shiftLeft(C, 8) + inputText[i];
		}

		for(int i=length*3;i<length*4;i++)
		{
			D = shiftLeft(D, 8) + inputText[i];
		}
		
		if(type_ID == 1)
		{
			System.out.println("\nThis is encryption code : ");
			assign1_Obj.encryption();
			
			StringBuilder sbencrypt = new StringBuilder();
			sbencrypt.append("Ciphertext: ");
			for(int i=0;i<Final_cipherText.length;i++){
				for(int j=0;j<7;j++){
					String x = (Integer.toHexString(Final_cipherText[i]).substring(j, j+2));
					sbencrypt.append(x + " ");
					j++;
				}
			}
			//sbencrypt.setLength(sbencrypt.length() - 1);
			System.out.println(sbencrypt);	
			try(  PrintWriter out = new PrintWriter( args[1] )  ){
			    out.println( sbencrypt );
			}

		}
		if(type_ID == 2)
		{
			System.out.println("\nThis is Decryption code : ");
			assign1_Obj.decryption();
			
			StringBuilder sbDecrypt = new StringBuilder();
			sbDecrypt.append("Plaintext: ");
			
			for(int i=0;i<Final_plainText.length;i++){
				int outTextLen = 0;
				for(int k= Integer.toHexString(Final_plainText[i]).length() ;k<8;k++){
					if( (outTextLen) %2 == 0)
					{	sbDecrypt.append(" 0");
						outTextLen++;
					}
					else
					{	sbDecrypt.append("0");
						outTextLen++;
					}
				}
				
				for(int j=0;j<Integer.toHexString(Final_plainText[i]).length();j++){
					if( (outTextLen) %2 == 0){
						sbDecrypt.append(" ").append(Integer.toHexString(Final_plainText[i]).substring(j, j+1));
						outTextLen++;
					}else{
						sbDecrypt.append( Integer.toHexString(Final_plainText[i]).substring(j, j+1) );
						outTextLen++;
					}
				}
				
			}
			//sbDecrypt.setLength(sbDecrypt.length() - 1);
			System.out.println(sbDecrypt);	
			try(  PrintWriter out = new PrintWriter( args[1] )  ){
			    out.println( sbDecrypt );
			}
		}
		in.close();
		
	}//End of main
}//End of class