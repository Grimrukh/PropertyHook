﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PropertyHook;

/// <summary>
/// Manages scanning for given AOBs (Arrays of Bytes) in a particular Process.
/// </summary>
public class AOBScanner
{
    const uint PAGE_EXECUTE_ANY = Kernel32.PAGE_EXECUTE | Kernel32.PAGE_EXECUTE_READ | Kernel32.PAGE_EXECUTE_READWRITE | Kernel32.PAGE_EXECUTE_WRITECOPY;

    readonly Dictionary<IntPtr, byte[]> ReadMemory;

    Process Process { get; }

    /// <summary>
    /// Creates a new AOBScanner for the given Process.
    /// </summary>
    public AOBScanner(Process process)
    {
        Process = process;
        var memRegions = new List<Kernel32.MEMORY_BASIC_INFORMATION>();
        IntPtr memRegionAddr = process.MainModule.BaseAddress;
        IntPtr mainModuleEnd = process.MainModule.BaseAddress + process.MainModule.ModuleMemorySize;
        uint queryResult;

        do
        {
            var memInfo = new Kernel32.MEMORY_BASIC_INFORMATION();
            queryResult = Kernel32.VirtualQueryEx(process.Handle, memRegionAddr, out memInfo, (IntPtr)Marshal.SizeOf(memInfo));
            if (queryResult != 0)
            {
                if ((memInfo.State & Kernel32.MEM_COMMIT) != 0 && (memInfo.Protect & Kernel32.PAGE_GUARD) == 0 && (memInfo.Protect & PAGE_EXECUTE_ANY) != 0)
                    memRegions.Add(memInfo);
                memRegionAddr = memInfo.BaseAddress + (int)memInfo.RegionSize;
            }
        } while (queryResult != 0 && (ulong)memRegionAddr < (ulong)mainModuleEnd);

        ReadMemory = new Dictionary<IntPtr, byte[]>();
        foreach (Kernel32.MEMORY_BASIC_INFORMATION memRegion in memRegions)
            ReadMemory[memRegion.BaseAddress] = Kernel32.ReadBytes(process.Handle, memRegion.BaseAddress, (uint)memRegion.RegionSize);
    }

    /// <summary>
    /// Add a memory region manually.
    /// </summary>
    public void AddMemRegion(IntPtr baseAddress, uint regionSize)
    {
        ReadMemory[baseAddress] = Kernel32.ReadBytes(Process.Handle, baseAddress, regionSize);
    }

    /// <summary>
    /// Scan for the given (non-nullable int) AOB in process memory.
    /// </summary>
    public IntPtr Scan(int[] aob)
    {
        foreach (IntPtr baseAddress in ReadMemory.Keys)
        {
            byte[] bytes = ReadMemory[baseAddress];
            if (TryScan(bytes, aob, out int index))
                return baseAddress + index;
        }

        return IntPtr.Zero;
    }

    /// <summary>
    /// Scan for `aob` and return all instances found.
    /// </summary>
    /// <param name="aob"></param>
    /// <returns></returns>
    public IntPtr[] ScanMultiple(int[] aob)
    {
        List<IntPtr> hits = new List<IntPtr>();
        foreach (IntPtr baseAddress in ReadMemory.Keys)
        {
            byte[] bytes = ReadMemory[baseAddress];
            int startIndex = 0;
            while (TryScan(bytes, aob, out int hitIndex, startIndex))
            {
                hits.Add(baseAddress + hitIndex);
                startIndex = hitIndex + aob.Length;
            }
        }

        return hits.ToArray();
    }

    /// <summary>
    /// Scan for the given (nullable) AOB in process memory.
    /// </summary>
    public IntPtr Scan(byte?[] aob)
    {
        int[] pattern = Unbox(aob);
        foreach (IntPtr baseAddress in ReadMemory.Keys)
        {
            byte[] bytes = ReadMemory[baseAddress];
            if (TryScan(bytes, pattern, out int index))
                return baseAddress + index;
        }

        return IntPtr.Zero;
    }

    // Using nullable byte for comparisons is very slow
    static int[] Unbox(byte?[] aob)
    {
        var pattern = new int[aob.Length];
        for (int i = 0; i < aob.Length; i++)
        {
            if (aob[i].HasValue)
                pattern[i] = aob[i].Value;
            else
                pattern[i] = -1;
        }
        return pattern;
    }

    static bool TryScan(byte[] text, int[] pattern, out int index, int startIndex = 0)
    {
        for (int i = startIndex; i < text.Length - pattern.Length; i++)
        {
            for (int j = 0; j < pattern.Length; j++)
            {
                if (pattern[j] != -1 && pattern[j] != text[i + j])
                {
                    break;
                }
                else if (j == pattern.Length - 1)
                {
                    index = i;
                    return true;
                }
            }
        }

        index = -1;
        return false;
    }

    /// <summary>
    /// Convert an array of hex bytes represented by a string, such
    /// as '8B 3F 93 ?', to a nullable byte array for scanning.
    /// 
    /// Question marks may be used to represent wild card bytes.
    /// </summary>
    public static byte?[] StringToAOB(string text)
    {
        string[] items = text.Split(' ');
        byte?[] aob = new byte?[items.Length];
        for (int i = 0; i < aob.Length; i++)
        {
            string item = items[i];
            if (item == "?")
                aob[i] = null;
            else
                aob[i] = byte.Parse(item, System.Globalization.NumberStyles.AllowHexSpecifier);
        }
        return aob;
    }
}