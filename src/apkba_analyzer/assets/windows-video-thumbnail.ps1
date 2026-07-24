[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VideoPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$source = @'
using System;
using System.Drawing;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct ApkbaSize {
    public int cx;
    public int cy;
    public ApkbaSize(int x, int y) { cx = x; cy = y; }
}

[Flags]
public enum ApkbaImageFlags {
    BiggerSizeOk = 0x01,
    ThumbnailOnly = 0x08
}

[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
 Guid("bcc18b79-ba16-442f-80c4-8a59c30c463b")]
interface IApkbaShellItemImageFactory {
    [PreserveSig]
    int GetImage(ApkbaSize size, ApkbaImageFlags flags, out IntPtr bitmap);
}

public static class ApkbaShellThumbnail {
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    static extern void SHCreateItemFromParsingName(
        string path,
        IntPtr context,
        ref Guid iid,
        [MarshalAs(UnmanagedType.Interface)] out IApkbaShellItemImageFactory factory
    );

    [DllImport("gdi32.dll")]
    static extern bool DeleteObject(IntPtr value);

    public static void Save(string input, string output) {
        Guid iid = new Guid("bcc18b79-ba16-442f-80c4-8a59c30c463b");
        IApkbaShellItemImageFactory factory;
        SHCreateItemFromParsingName(input, IntPtr.Zero, ref iid, out factory);
        IntPtr bitmap;
        int result = factory.GetImage(
            new ApkbaSize(720, 1280),
            ApkbaImageFlags.BiggerSizeOk | ApkbaImageFlags.ThumbnailOnly,
            out bitmap
        );
        if (result != 0) Marshal.ThrowExceptionForHR(result);
        try {
            using (Image image = Image.FromHbitmap(bitmap)) {
                image.Save(output, System.Drawing.Imaging.ImageFormat.Png);
            }
        }
        finally {
            DeleteObject(bitmap);
            Marshal.ReleaseComObject(factory);
        }
    }
}
'@

Add-Type -TypeDefinition $source -ReferencedAssemblies System.Drawing
[ApkbaShellThumbnail]::Save(
    (Resolve-Path -LiteralPath $VideoPath).Path,
    [System.IO.Path]::GetFullPath($OutputPath)
)
