using System;
using System.IO;
using System.Text;

namespace RSAEncryption
{
    class Program
    {
        static void Main(string[] args)
        {

            //Duomenu ivedimas
            Console.WriteLine("Enter two prime numbers (p and q):");
            int p = int.Parse(Console.ReadLine());
            int q = int.Parse(Console.ReadLine());
            int n = p * q;
            int FiN = (p - 1) * (q - 1);
            int e = FindPublicExponent(FiN);
            int d = FindPrivateExponent(FiN, e);

            Console.WriteLine("Public key (n, e): ({0}, {1})", n, e);
            Console.WriteLine("Private key (n, d): ({0}, {1})", n, d);

            Console.WriteLine("Enter the plaintext:");
            string plaintext = Console.ReadLine();



            //Sifravimas
            string ciphertext = Encrypt(plaintext, n, e);



            Console.WriteLine("Ciphertext: {0}", ciphertext);
            Console.WriteLine("Writing ciphertext and public key to file...");

            //Duomenu issaugojimas i failus
            using (StreamWriter writer = new StreamWriter("ciphertext.txt"))
            {
                writer.WriteLine(ciphertext);
            }
            using (StreamWriter writer = new StreamWriter("publickey.txt"))
            {
                writer.WriteLine("{0},{1}", n, e);
            }



            //Duomenu skaitymas is failu
            Console.WriteLine("Reading ciphertext and public key from file...");
            string readCiphertext, publicKeyStr;
            using (StreamReader reader = new StreamReader("ciphertext.txt"))
            {
                readCiphertext = reader.ReadLine();
            }
            using (StreamReader reader = new StreamReader("publickey.txt"))
            {
                publicKeyStr = reader.ReadLine();
            }
            string[] publicKeyParts = publicKeyStr.Split(',');
            int readN = int.Parse(publicKeyParts[0]);
            int readE = int.Parse(publicKeyParts[1]);



            //Desifravimas
            Console.WriteLine("Decrypting ciphertext...");
            string decryptedtext = Decrypt(readCiphertext, readN, d);

            Console.WriteLine("Decrypted text: {0}", decryptedtext);
        }



        //viesosios eksponentes radimas (e)
        static int FindPublicExponent(int FiN)
        {
            for (int e = 2; e < FiN; e++)
            {
                if (IsCoprime(e, FiN))
                {
                    return e;
                }
            }
            return -1;
        }

        //Patikrina ar abu skaiciai yra pirminiai
        static bool IsCoprime(int a, int b)
        {
            int gcd = FindGCD(a, b);
            return gcd == 1;
        }

        //Suranda didziausia bendra dalikli
        static int FindGCD(int a, int b)
        {
            if (a == 0)
            {
                return b;
            }
            return FindGCD(b % a, a);
        }

        //Privataus rakto radimas (d)
        static int FindPrivateExponent(int FiN, int e)
        {
            int d = 1;
            while (((d * e) % FiN) != 1)
            {
                d++;
            }
            return d;
        }

        //Sifravimo algoritmas
        static string Encrypt(string plaintext, int n, int e)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(plaintext);
            string ciphertext = "";
            foreach (byte b in bytes)
            {
                int m = (int)b;
                int crypted = ModPow(m, e, n);
                ciphertext += crypted.ToString() + " ";
            }
            return ciphertext;
        }

        //Desifravimo algorimtas
        static string Decrypt(string ciphertext, int n, int d)
        {
            string[] parts = ciphertext.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            byte[] bytes = new byte[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                int crypted = int.Parse(parts[i]);
                int decrypted = ModPow(crypted, d, n);
                bytes[i] = (byte)decrypted;
            }
            string plaintext = Encoding.UTF8.GetString(bytes);
            return plaintext;
        }


        //RSA algoritmo sifravimo/desifravimo formule
        static int ModPow(int baseNum, int exponent, int modulus)
        {
            if (modulus == 1)
            {
                return 0;
            }

            int result = 1;
            baseNum = baseNum % modulus;
            while (exponent > 0)
            {
                if ((exponent % 2) == 1)
                {
                    result = (result * baseNum) % modulus;
                }
                exponent = exponent >> 1;
                baseNum = (baseNum * baseNum) % modulus;
            }

            return result;
        }

    }
}