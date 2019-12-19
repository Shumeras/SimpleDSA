using System;
using System.Numerics;
using System.Security.Cryptography;

namespace DSA
{
    static class DSA
    {
        #region Default Properties
        
        const long N = 1024/8;        
        const long L = 160/8;         

        #endregion

        // Using Miller-Rabin test to discern primes
        static bool isProbablyPrime(BigInteger number)
        {
            if(number.IsEven || number < 2)
                return false;

            BigInteger k, m;
            
            for(k = 0;;k++)
            {
                BigInteger remainder, tmp;
                tmp = BigInteger.DivRem(number-1, new BigInteger(Math.Pow(2, (double)k+1)), out remainder);
                
                if(remainder.IsZero)
                    m = tmp;
                else
                    break;
            }

            var b = BigInteger.ModPow(2, m, number);
            if(b == 1 || b == -1)
                return true;

            for(; ; b = BigInteger.ModPow(b, 2, number))
            {
                if(b == 1 || k-- < 0)
                    return false;
                else if(b == number-1)
                    return true;
            }
        }

        static BigInteger getRandomNumber(long length)
        {
            var rng = new Random();
            var buffer = new byte[length];
            rng.NextBytes(buffer);
            var result = new BigInteger(buffer);    // Can't use the isUnsigned parameters as it can produce an extra byte when converted 
            return result*result.Sign;              // Multiplying by sign makes sure the number is positive, to avoid checking negative numbers;
        }

        static BigInteger getRandomNumber(BigInteger begin, BigInteger end)
        {
            if(begin >= end ) 
                throw new InvalidOperationException();

            var result = new BigInteger();
            
            do
            {   
                result = BigInteger.ModPow(getRandomNumber(end.GetByteCount()+1), 1, end);
            }
            while(result < begin || result > end);

            return result;
        }

        //Extended Euclid Algorithm
        static BigInteger modInverse(BigInteger a, BigInteger m) 
        { 
            // BigInteger m0 = m; 
            // BigInteger y = 0, x = 1; 

            // if (m == 1) 
            //     return 0; 
    
            // while (a > 1) 
            // { 
            //     BigInteger q = a / m; 
            //     BigInteger t = m; 
    
            //     m = a % m; 
            //     a = t; 
            //     t = y; 
    
            //     y = x - q * y; 
            //     x = t; 
            // } 
    
            // return x * x.Sign; 
            return BigInteger.ModPow(a, m-2,m);
        }
    
        static BigInteger getRandomPrime(long length)
        {
            var result = getRandomNumber(length);
            
            if(result.IsEven)
                result++;

            for(ulong i = 1; ; result+=2, i++)  //Shooting randomly actually producess a better discovery time, but I don't like the undeterministic behavior
                if(isProbablyPrime(result))
                {
                    // System.Console.WriteLine("Prime found in {0} attempts: {1}", i, result);
                    return result;
                }
                else if(result.GetByteCount() > length) //just in case
                    result = getRandomNumber(length);
        } 

        static (BigInteger p, BigInteger q) generatePrimes(long N, long L)
        {
            BigInteger p, q, k;

            for(long i = 1 ;;q=getRandomPrime(L),  i++)
            {
                k = getRandomNumber((N-L));
                p = (k*q)+1;

                if(isProbablyPrime(p))
                {   
                    // System.Console.WriteLine("Pair found in {0} attempts:", i);  
                    // System.Console.WriteLine("p found: ({0}bit): {1}", p.GetByteCount()*8, p);
                    // System.Console.WriteLine("q found: ({0}bit): {1}", q.GetByteCount()*8, q);
                    return (p, q);
                }
            }
        }   
     

        public static ((BigInteger p, BigInteger q, BigInteger a, BigInteger b) publicKey, BigInteger privateKey) generateKeys(long N = N, long L = L) 
        {
            var (p, q) = generatePrimes(N, L);
            
            BigInteger a, b, d;
            
            for(BigInteger g = 2; g < p; g++)
            {
                a = BigInteger.ModPow(g, (p-1)/q, p);
                if(!a.IsOne)
                    break;
            }

            //System.Console.WriteLine("a: " + a);
            d = getRandomNumber(1, q);          // [1, q) == [1, q-1]
            b = BigInteger.ModPow(a, d, p);
            //System.Console.WriteLine("b: " + b);
            //System.Console.WriteLine("d: " + d);
            
            return ((p,q,a,b), d);
        }

        public static (BigInteger r, BigInteger s) sign(
            (BigInteger p, BigInteger q, BigInteger a, BigInteger b) publicKey, 
            BigInteger privateKey, 
            byte[] message)
        {
            var sha = SHA1.Create();
            var ephimeralKey = getRandomNumber(1, publicKey.q);

            var r = BigInteger.ModPow(BigInteger.ModPow(publicKey.a, ephimeralKey, publicKey.p), 1, publicKey.q);

            var s = ((new BigInteger(sha.ComputeHash(message), true) + (privateKey * r)) * modInverse(ephimeralKey, publicKey.q)) % publicKey.q;
            
            sha.Dispose();
            return (r, s);
        }

        public static bool validate(
            (BigInteger p, BigInteger q, BigInteger a, BigInteger b) publicKey, 
            (BigInteger r, BigInteger s) signature,
            byte[] message)
        {
            var sha = SHA1.Create();

            var invS = modInverse(signature.s, publicKey.q);
            var messageHash = new BigInteger(sha.ComputeHash(message), true);

            var x = (invS*messageHash) % publicKey.q;
            var y = (invS*signature.r) % publicKey.q;

            
            var V = BigInteger.ModPow(
                BigInteger.ModPow(
                    BigInteger.ModPow(publicKey.a, x, publicKey.p)*BigInteger.ModPow(publicKey.b, y, publicKey.p),
                    1,
                    publicKey.p),
                1, 
                publicKey.q);

            // System.Console.WriteLine("hash: " + messageHash);
            // System.Console.WriteLine("s: " + invS);
            // System.Console.WriteLine("x: " + x);
            // System.Console.WriteLine("y: " + y);
            // System.Console.WriteLine("V: " + V);
            sha.Dispose();

            return (V == signature.r);           
        } 



    }

}