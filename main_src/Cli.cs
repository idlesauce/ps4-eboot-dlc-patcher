using System;
using System.CommandLine;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace ps4_eboot_dlc_patcher;

/// <summary>
/// Fully-featured CLI entry-point built on <c>System.CommandLine</c>.  The file is additive: nothing here
/// touches the Spectre.Console driven interactive flow – if no sub-command is supplied the application
/// drops straight back to <c>RunInteractiveAsync</c> in <c>Program.cs</c>.
/// </summary>
public static class Cli
{
    public static async Task<int> InvokeAsync(string[] args)
    {
        // ─────────────────────────────────────────────────────────────────────────────
        // root command
        // ─────────────────────────────────────────────────────────────────────────────
        var root = new RootCommand("PS4-/PS5-EBOOT-DLC-Patcher – non-interactive CLI")
        {
            TreatUnmatchedTokensAsErrors = true
        };

        // ─────────────────────────────────────────────────────────────────────────────
        // patch — patch one or more executables so they can load DLCs
        // ─────────────────────────────────────────────────────────────────────────────
        var execOption = new Option<FileInfo[]>(aliases: new[] { "--exec", "-e" },
                                               description: "Path(s) to the ELF(s) to patch")
        {
            Arity = ArgumentArity.OneOrMore
        };

        var dlcOption = new Option<FileInfo[]>(aliases: new[] { "--dlc", "-d" },
                                              description: "Path(s) to DLC PKG(s)")
        {
            Arity = ArgumentArity.OneOrMore
        };

        var outputDirOption = new Option<DirectoryInfo?>(aliases: new[] { "--output-dir", "-o" },
                                                         description: "Output directory for patched assets");

        var forceOption = new Option<bool>(aliases: new[] { "--force-in-eboot", "-f" },
                                           description: "Force the in-EBOOT loader variant (advanced)");

        var patchCmd = new Command("patch", "Patch executable(s) so they resolve DLC look-ups via dlcldr.prx");
        patchCmd.AddOption(execOption);
        patchCmd.AddOption(dlcOption);
        patchCmd.AddOption(outputDirOption);
        patchCmd.AddOption(forceOption);

        patchCmd.SetHandler(async (FileInfo[] exec, FileInfo[] dlc, DirectoryInfo? outDir, bool force) =>
        {
            var execPaths = exec.Select(f => f.FullName).ToList();
            var dlcPaths  = dlc.Select(f => f.FullName).ToList();
            var output    = (outDir ?? new DirectoryInfo(Path.Combine(Environment.CurrentDirectory,
                                                                      "eboot_patcher_output"))).FullName;

            // ── Confirmation banner (mirrors interactive flavour) ──
            Console.WriteLine($"[INFO] Parsed {dlcPaths.Count} DLC(s)");
            Console.WriteLine($"> Patch {execPaths.Count} executable(s) with {dlcPaths.Count} DLC(s)");
            Console.WriteLine();

            await Program.PatchExecutablesNonInteractive(execPaths, dlcPaths, output, force);
        }, execOption, dlcOption, outputDirOption, forceOption);

        root.AddCommand(patchCmd);

        // ─────────────────────────────────────────────────────────────────────────────
        // extract-dlc — extract extra-data DLCs into dlcXX folders in an Image0 tree
        // ─────────────────────────────────────────────────────────────────────────────
        var extractDlcOption = new Option<FileInfo[]>(aliases: new[] { "--dlc", "-d" },
                                                      description: "DLC PKGs containing extra data")
        {
            Arity = ArgumentArity.OneOrMore
        };

        var image0Option = new Option<DirectoryInfo>(aliases: new[] { "--image0", "-i" },
                                                     description: "Update's Image0 directory where dlcXX folders will be created")
        {
            IsRequired = true
        };

        var extractCmd = new Command("extract-dlc", "Extract extra-data DLCs into dlcXX folders under Image0");
        extractCmd.AddOption(extractDlcOption);
        extractCmd.AddOption(image0Option);

        extractCmd.SetHandler(async (FileInfo[] dlc, DirectoryInfo image0) =>
        {
            Console.WriteLine($"[INFO] Parsed {dlc.Length} DLC(s)");
            Console.WriteLine($"> Extract {dlc.Length} DLC(s) into Image0: {image0.FullName}");
            Console.WriteLine();

            await Program.ExtractDlcsNonInteractive(image0.FullName,
                                                    dlc.Select(f => f.FullName).ToList());
        }, extractDlcOption, image0Option);

        root.AddCommand(extractCmd);

        // ─────────────────────────────────────────────────────────────────────────────
        // list-dlc — pretty-print DLC metadata from PKGs (entitlement label, status, key)
        // ─────────────────────────────────────────────────────────────────────────────
        var listDlcOption = new Option<FileInfo[]>(aliases: new[] { "--dlc", "-d" },
                                                   description: "PKG(s) to inspect")
        {
            Arity = ArgumentArity.OneOrMore
        };

        var listDlcCmd = new Command("list-dlc", "Print DLC metadata extracted from one or more PKGs");
        listDlcCmd.AddOption(listDlcOption);

        listDlcCmd.SetHandler((FileInfo[] dlcPkgs) =>
        {
            Console.WriteLine($"[INFO] Parsed {dlcPkgs.Length} DLC(s)");
            Console.WriteLine("> Listing metadata\n");

            foreach (var pkg in dlcPkgs)
            {
                var info = Program.TryParseDlc(pkg.FullName);
                Console.WriteLine(info != null ? info.ToEncodedString()
                                               : $"{pkg.Name}: parse failed");
            }
        }, listDlcOption);

        root.AddCommand(listDlcCmd);

        // Additional specialised sub-commands can be added here in future (e.g. list-exec-in-pkg)

        // ─────────────────────────────────────────────────────────────────────────────
        return await root.InvokeAsync(args);
    }
}
