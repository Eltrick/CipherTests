using Eltrick.Ciphers;
using CipherWords;

NonCipherMachineHelpers _helper = new();

Console.WriteLine(_helper.BaseConverterResults(_helper.BaseConverter(314562, 10, 7)));
Console.WriteLine(_helper.BaseConverterResults(_helper.BaseConverter(452163, 10, 8)));
Console.WriteLine(_helper.BaseConverterResults(_helper.BaseConverter(612534, 10, 9)));
Console.WriteLine(_helper.BaseConverterResults(_helper.BaseConverter(516234, 10, 11)));