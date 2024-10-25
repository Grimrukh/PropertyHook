using System;
using System.Diagnostics;

namespace PropertyHook;

/// <summary>
/// Designed for scanning for AOBs in arbitrarily large memory regions, which are consumed as overlapping chunks.
///
/// Does not yet support wild cards; only `byte[]` patterns.
/// </summary>
public static class AOBChunkScanner
{
    /// <summary>
    /// Search given region of `process` memory for given `searchPattern`.
    /// </summary>
    /// <param name="process"></param>
    /// <param name="startAddress"></param>
    /// <param name="regionSize"></param>
    /// <param name="searchPattern"></param>
    /// <returns></returns>
    public static IntPtr SearchMemory(Process process, IntPtr startAddress, ulong regionSize, byte[] searchPattern)
    {
        const int chunkSize = 4096; // Read memory in 4KB chunks
        int overlap = searchPattern.Length - 1;
        byte[] buffer = new byte[chunkSize + overlap]; // Include overlap for boundary handling

        IntPtr currentAddress = startAddress;
        ulong bytesRemaining = regionSize;

        while (bytesRemaining > 0)
        {
            uint bytesToRead = (uint)Math.Min(bytesRemaining, chunkSize);
            IntPtr nSize = (IntPtr)(bytesToRead + overlap);

            // Read memory with overlap.
            if (Kernel32.ReadProcessMemory(process.Handle, currentAddress, buffer, nSize, out IntPtr bytesRead))
            {
                // Search for the pattern in the buffer.
                int index = SearchBuffer(buffer, (int)bytesRead, searchPattern);
                if (index != -1)
                {
                    // Pattern found, calculate the exact memory address.
                    return IntPtr.Add(currentAddress, index);
                }
            }

            // Move to the next chunk, accounting for overlap.
            currentAddress = IntPtr.Add(currentAddress, chunkSize);
            bytesRemaining -= bytesToRead;
        }
        
        Console.WriteLine("Pattern not found.");

        // Pattern not found.
        return IntPtr.Zero;
    }

    static int SearchBuffer(byte[] buffer, int bufferLength, byte[] pattern)
    {
        // Simple byte-by-byte search (could be optimized with algorithms like Boyer-Moore).
        for (int i = 0; i <= bufferLength - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (buffer[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return i; // Return the index of the match
            }
        }

        return -1; // No match found
    }
}