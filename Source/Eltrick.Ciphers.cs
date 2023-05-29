using CipherWords;
using System.Text.RegularExpressions;
using Emik.Numerics.Fractions;

namespace Eltrick.Ciphers;

// Cipher Machine - Generalised HI
internal class HillCipher
{
    public int Size { get; }
    public int Modulus { get; }

    private readonly int[,] _matrix;
    
    public HillCipher(int size, int modulus)
    {
        Size = size;
        Modulus = modulus < 13 ? 13 : modulus > int.MaxValue / 2 ? int.MaxValue / 2 : modulus;
        _matrix = new int[size, size];

        do
        {
            for (int i = 0; i < size; i++)
            for (int j = 0; j < size; j++)
                SetEntry(i, j, NonCipherMachineHelpers.random.Next(0, Modulus));
        } while (Operators.GreatestCommonDivisor(Determinant(), Modulus) != 1);
    }

    public void SetEntry(int i, int j, int value) => _matrix[i, j] = value;

    public int GetEntry(int i, int j) => _matrix[i, j];

    public HillCipher SubMatrix(int a, int b)
    {
        HillCipher matrix = new HillCipher(Size - 1, Modulus);

        int entry = 0;
        for (int i = 0; i < Size; i++)
        for (int j = 0; j < Size; j++)
        {
            if (i == a || j == b)
                continue;
            matrix.SetEntry(entry / matrix.Size, entry % matrix.Size, _matrix[i, j]);
            entry++;
        }

        return matrix;
    }

    public int Determinant()
    {
        if (Size == 0)
            return 1;

        int determinant = 0;

        for (int i = 0; i < Size; i++)
            determinant +=
                (_matrix[0, i] * SubMatrix(0, i).Determinant() * (int)Math.Pow(-1, i)).PositiveModulo(Modulus);

        determinant %= Modulus;

        return determinant;
    }

    public HillCipher Cofactor()
    {
        HillCipher matrix = new HillCipher(Size, Modulus);

        for (int i = 0; i < Size; i++)
        for (int j = 0; j < Size; j++)
            matrix.SetEntry(i, j, (SubMatrix(i, j).Determinant() * (int)Math.Pow(-1, i + j)).PositiveModulo(Modulus));

        return matrix;
    }

    public HillCipher Transpose()
    {
        HillCipher matrix = new HillCipher(Size, Modulus);

        for (int i = 0; i < Size; i++)
        for (int j = 0; j < Size; j++)
            matrix.SetEntry(j, i, _matrix[i, j]);

        return matrix;
    }

    public HillCipher Adjugate() => Cofactor().Transpose();

    public static int MultiplicativeInverse(int value, int modulus = int.MaxValue)
    {
        for (int i = 0; i < modulus; i++)
            if ((i * value) % modulus == 1)
                return i;
        return -1;
    }

    public HillCipher InverseMatrix() => Adjugate().ScalarMultiplication(MultiplicativeInverse(Determinant(), Modulus));

    public HillCipher ScalarMultiplication(int scalar)
    {
        HillCipher matrix = new HillCipher(Size, Modulus);

        for (int i = 0; i < Size; i++)
        for (int j = 0; j < Size; j++)
            matrix.SetEntry(i, j, (_matrix[i, j] * scalar).PositiveModulo(Modulus));

        return matrix;
    }

    public int[] MatrixVectorMultiplication(int[] vector)
    {
        int[] result = new int[Size];

        for (int i = 0; i < Size; i++)
            result[i] = Enumerable.Range(0, Size).Select(x => (GetEntry(i, x) * vector[x]).PositiveModulo(Modulus))
                .Sum().PositiveModulo(Modulus);

        return result;
    }

    public override string ToString() => string.Join(", ", _matrix.Cast<int>().ToArray().Select(x => x.ToString()).ToArray());

    public int[] MatrixToArray() => _matrix.Cast<int>().ToArray();
}

// Cipher Machine - QR
internal class QuadrantReflectionCipher
{
    public int QuadrantSize = 5;
    public int StartingQuadrant;

    private readonly string[][,] _quadrants;
    private string[] _keystrings;
    private const string _alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private char[] _removedLetters;
    private bool[] _keystringOrder;

    public QuadrantReflectionCipher()
    {
        _quadrants = new string[4][,];
        StartingQuadrant = 0;

        for (int i = 0; i < _quadrants.Length; i++)
            _quadrants[i] = new string[QuadrantSize, QuadrantSize];

        _keystrings = new string[_quadrants.Length];
        _removedLetters = new char[_quadrants.Length];
        _keystringOrder = new bool[_quadrants.Length];

        Initialise();
    }

    private void Initialise()
    {
        // Picks keywords and ignored letters.
        _removedLetters = Enumerable.Range(0, _quadrants.Length)
            .Select(_ => _alphabet[NonCipherMachineHelpers.random.Next(0, _alphabet.Length)]).ToArray();
        _keystrings = Enumerable.Range(0, _quadrants.Length)
            .Select(_ => Wordlist.wordlist[NonCipherMachineHelpers.random.Next(0, Wordlist.wordlist.Length)]).ToArray();
        _keystringOrder = Enumerable.Range(0, _quadrants.Length).Select(_ => NonCipherMachineHelpers.random.Next(0, 2) == 1)
            .ToArray();

        // Removes duplicate characters, keeping their first occurrences.
        for (int i = 0; i < _keystrings.Length; i++)
        {
            string s = "";

            for (int j = 0; j < _keystrings[i].Length; j++)
                if (!s.Contains(_keystrings[i][j].ToString()))
                    s += _keystrings[i][j].ToString();

            _keystrings[i] = s;

            // Removes ignored letter from keystrings.
            _keystrings[i] = Regex.Replace(_keystrings[i], $"{_removedLetters[i]}", "");
        }

        // Creates keystrings from keywords.
        for (int i = 0; i < _keystrings.Length; i++)
        {
            string a = _alphabet;
            a = Regex.Replace(a, $"[{_keystrings[i] + _removedLetters[i]}]", "");

            if (_keystringOrder[i])
                _keystrings[i] = a + _keystrings[i];
            else
                _keystrings[i] += a;
        }

        // Fills quadrants with keystrings.
        for (int i = 0; i < _quadrants.Length; i++)
        {
            for (int j = 0; j < QuadrantSize; j++)
            for (int k = 0; k < QuadrantSize; k++)
                _quadrants[i][j, k] = _keystrings[i][5 * j + k].ToString();
        }
    }

    public string Encrypt(string word, int startingQuadrant)
    {
        string result = "";
        int currentQuadrant = startingQuadrant;

        foreach (var c in word)
        {
            int[] position = Find(_quadrants[currentQuadrant], c.ToString());

            if (position[0] == -1)
                result += c.ToString();
            else
            {
                if (currentQuadrant % 2 == 0)
                    result += _quadrants[(currentQuadrant - 1).PositiveModulo(_quadrants.Length)][
                        QuadrantSize - 1 - position[0], position[1]];
                else
                    result += _quadrants[(currentQuadrant - 1).PositiveModulo(_quadrants.Length)][position[0],
                        QuadrantSize - 1 - position[1]];
            }

            currentQuadrant = (currentQuadrant - 1).PositiveModulo(_quadrants.Length);
        }

        return result;
    }

    public string Decrypt(string word, int startingQuadrant)
    {
        string result = "";
        int currentQuadrant = (startingQuadrant - 1).PositiveModulo(_quadrants.Length);

        foreach (var c in word)
        {
            int[] position = Find(_quadrants[currentQuadrant], c.ToString());

            if (position[0] == -1)
                result += c.ToString();
            else
            {
                if (currentQuadrant % 2 == 1)
                    result += _quadrants[(currentQuadrant + 1).PositiveModulo(_quadrants.Length)][
                        QuadrantSize - 1 - position[0], position[1]];
                else
                    result += _quadrants[(currentQuadrant + 1).PositiveModulo(_quadrants.Length)][position[0],
                        QuadrantSize - 1 - position[1]];
            }

            currentQuadrant = (currentQuadrant + 1).PositiveModulo(_quadrants.Length);
        }

        return result;
    }

    public string GetKeystrings() => string.Join(";", _keystrings);

    private static int[] Find(string[,] quadrant, string letter)
    {
        for (int i = 0; i < (int)Math.Sqrt(quadrant.Length); i++)
        for (int j = 0; j < (int)Math.Sqrt(quadrant.Length); j++)
            if (quadrant[i, j] == letter)
                return new[] { i, j };
        return new[] { -1, -1 };
    }
}

// Only a funny test thing. Might be used somewhere.
internal class ContinuedFractionCipher
{
    public string Word;

    public ContinuedFractionCipher(string word)
    {
        Word = word;
        Encrypt(Word);
    }

    public Fraction[] Encrypt(string word)
    {
        Fraction result = new(0);

        char[] reversedWord = word.ToCharArray();
        Array.Reverse(reversedWord);

        string evaluate = string.Join("", reversedWord.Select(x => x.ToString()).ToArray());

        foreach (var c in evaluate)
            result = 1 / (new Fraction(c - 'A' + 1) + result);

        Fraction multiplier = new Fraction(NonCipherMachineHelpers.random.Next(1, short.MaxValue / 2));
        do
        {
            multiplier /= NonCipherMachineHelpers.random.Next(1, short.MaxValue);
        } while (multiplier.Numerator >= multiplier.Denominator);

        Fraction offset = new Fraction(NonCipherMachineHelpers.random.Next(1, short.MaxValue));
        do
        {
            offset /= NonCipherMachineHelpers.random.Next(1, short.MaxValue);
        } while (offset.Numerator >= offset.Denominator);

        result = result * multiplier + offset;

        return new[] { result, multiplier, offset };
    }
}

internal class PositionalComponentTranspositionCipher
{
    public string Word, Keyword, Keystring;

    /// <summary>
    /// Positional Component Transposition Cipher
    /// Turns each character into its positional equivalent, then converts each position into ternary.
    /// For each n'th digit in that sequence of ternary numbers, apply a transformation to them as a
    /// group, changing their positions, and outputting the orders used along with the result.
    /// If a given set of transpositions returns any number of 000 triplets, change one of the
    /// three transpositions such that it does not happen, then convert each new 3-digit ternary number back into
    /// its corresponding letter.
    ///
    /// Possible TODO: Add a keystring(?) such that the positional equivalents are different every time.
    /// </summary>
    /// <param name="word">The word to encrypt.</param>
    /// <param name="keyword">The keyword to make a keystring out of.</param>
    public PositionalComponentTranspositionCipher(string word, string keyword)
    {
        Word = word;
        Keyword = keyword;
        Keystring = NonCipherMachineHelpers.CreateKeystring(Keyword, NonCipherMachineHelpers.random.Next(0, 2) == 1);
    }

    public string Encrypt(string word)
    {
        string result = "";

        return result;
    }

    public string GetKeystring() => Keystring;
}

internal static class Operators
{
    internal static int PositiveModulo(this int i, int j) => (i % j + j) % j;
    
    public static int GreatestCommonDivisor(int a, int b)
    {
        while (a * b != 0)
        {
            int s = a % b;
            a = b;
            b = s;
        }

        return new[] { a, b }.Max();
    }
}

internal class NonCipherMachineHelpers
{
    internal static readonly Random random = new();

    /// <summary>
    /// Creates a keystring.
    /// </summary>
    /// <param name="keyword">The keyword to make the keystring out of.</param>
    /// <param name="front">Determines if the keyword is put at the front of the string or not.</param>
    /// <returns>A Keystring</returns>
    public static string CreateKeystring(string keyword, bool front)
    {
        string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        string noDuplicates = "";
        foreach (char x in keyword)
            if (noDuplicates.Contains(x))
                noDuplicates += x.ToString();

        alphabet = Regex.Replace(alphabet, "[" + noDuplicates + "]", "");

        return front ? noDuplicates + alphabet : alphabet + noDuplicates;
    }

    /// <summary>
    /// Converts a number from base to base.
    /// </summary>
    /// <param name="number">The number to convert</param>
    /// <param name="baseFrom">The base to convert from</param>
    /// <param name="baseTo">The base to convert to</param>
    /// <param name="alphabet">String to reference when converting bases</param>
    /// <returns>An array of numbers representing the number in baseTo</returns>
    public static ulong[] BaseConverter(string number, ulong baseFrom, ulong baseTo, string alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_")
    {
        ulong baseTen = 0;
        List<ulong> results = new List<ulong>();

        for (int i = 0; i < number.Length; i++)
            baseTen += (ulong)alphabet.IndexOf(number[i]) * (ulong)Math.Pow(baseFrom, number.Length - 1 - i);
        
        do
        {
            results.Add(baseTen % baseTo);
            baseTen /= baseTo;
        } while (baseTen != 0);

        results.Reverse();

        return results.ToArray();
    }

    /// <summary>
    /// Converts the results from BaseConverter to a string.
    /// </summary>
    /// <param name="results">Results from BaseConverter</param>
    /// <param name="alphabet">Alphabet used in BaseConverter</param>
    /// <returns>A string representing the results</returns>
    public static string BaseConverterResults(ulong[] results,
        string alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_") => string.Join("",
        Enumerable.Range(0, results.Length).Select(x => alphabet[(int)results[x]]));
}