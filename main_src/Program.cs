using Iced.Intel;
using LibOrbisPkg.PFS;
using LibOrbisPkg.PKG;
using LibOrbisPkg.Util;
using ps4_eboot_dlc_patcher.Ps4ModuleLoader;
using Spectre.Console;
using System.Buffers.Binary;
using System.IO.MemoryMappedFiles;
using System.Text;

namespace ps4_eboot_dlc_patcher;

internal class Program
{
    static async Task Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (e, a) =>
        {
            ConsoleUi.LogError(((Exception)a.ExceptionObject).Message);
            AnsiConsole.WriteLine("Press any key to exit...");
            Console.ReadKey();
            Environment.Exit(1);
        };

        /* ─────────────────────────────────────────────────────────────── */
        /*  CLI short-circuit                                              */
        /* ─────────────────────────────────────────────────────────────── */
        if (args.Length > 0 &&
            !args[0].EndsWith(".pkg", StringComparison.OrdinalIgnoreCase) &&
            !args[0].EndsWith(".elf", StringComparison.OrdinalIgnoreCase) &&
            !args[0].Equals("interactive", StringComparison.OrdinalIgnoreCase))
        {
            Environment.Exit(await Cli.InvokeAsync(args));   // ⇢ System.CommandLine
            return;                                          // defensive – never reached
        }

        var panel = new Panel(new Markup("[b]PS4 EBOOT DLC Patcher[/]").Centered());
        panel.Border = BoxBorder.Rounded;
        panel.Expand();
        AnsiConsole.Write(panel);

        List<string> dlcPkgs = new();
        List<string> executables = new();
        foreach (var arg in args)
        {

            if (File.Exists(arg) && Path.GetExtension(arg).Equals(".pkg", StringComparison.InvariantCultureIgnoreCase))
            {
                dlcPkgs.Add(arg);
            }
            else if (File.Exists(arg) && Path.GetExtension(arg).Equals(".elf", StringComparison.InvariantCultureIgnoreCase))
            {
                executables.Add(arg);
            }
            else
            {
                ConsoleUi.LogWarning($"Ignoring unknown file ({arg})");
            }
        }

        List<DlcInfo>? dlcInfos = new();

        foreach (var dlcPkg in dlcPkgs)
        {
            try
            {
                var dlcInfo = DlcInfo.FromDlcPkg(dlcPkg);
                dlcInfos.Add(dlcInfo);
            }
            catch (Exception ex)
            {
                ConsoleUi.LogError(ex.Message + $" ({dlcPkg})");
            }
        }

        if (dlcInfos.Count != dlcPkgs.Count)
        {
            int unsuccesful = dlcPkgs.Count - dlcInfos.Count;
            var res = ConsoleUi.Confirm($"{unsuccesful} DLCs failed to parse, countiue with {dlcInfos.Count} out of {dlcPkgs.Count} DLCs?");

            if (!res)
            {
                return;
            }
        }
        else if (dlcInfos.Count > 0)
        {
            ConsoleUi.LogInfo($"Parsed {dlcInfos.Count} DLCs");
        }

        if (dlcPkgs.Count == 0)
        {
            var res = ConsoleUi.Confirm("No dlc pkgs provided as arguments, do you want to manually input their info?");
            if (res)
            {
                dlcInfos.AddRange(ManualDlcInfoInput());
            }
        }

        if (dlcInfos.Count == 0)
        {
            ConsoleUi.LogError("No DLCs to patch");
            return;
        }

        if (executables.Count == 0)
        {
            var res = ConsoleUi.Confirm("No executable(s) provided as arguments, do you want to manually enter them?");
            if (res)
            {
                executables.AddRange(ExecutablePathsInput());
            }
        }

        bool exit = false;
        while (!exit)
        {
            var choice1 = $"Patch {executables.Count} executable(s) with {dlcInfos.Count} DLC(s)";
            var choice2 = "Print DLC infos";
            var choice3 = "Enter more dlc infos";
            var choice4 = "Enter more executables";
            var choice6 = "Extract w/ extra data dlcs into dlcXX folders";
            var choice5 = "Exit";

            List<string> kwuafh =
            [
                choice1,
                choice2,
                choice3,
                choice4,
                choice6,
                choice5
            ];

            var choice_dbg_1 = $"Patch {executables.Count} executable(s) with {dlcInfos.Count} DLC(s) [[FORCE IN EBOOT]]";
#if ALLOW_FORCE_IN_EBOOT
            kwuafh.Add(choice_dbg_1);
#endif

            var menuChoice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("Whats next?")
                    .PageSize(10)
                    .AddChoices(
                    kwuafh
                    ));


            if (menuChoice == choice1 || menuChoice == choice_dbg_1)
            {
                if (executables.Count == 0)
                {
                    ConsoleUi.LogError("No executables to patch");
                    continue;
                }

                // get path of this program
                var programPath = AppContext.BaseDirectory;

                // create new folder for output
                var outDir = Path.Combine(programPath, "eboot_patcher_output");

                if (!Directory.Exists(outDir))
                {
                    Directory.CreateDirectory(outDir);
                }

                // reorder dlcList so that PSAC dlcs are first but otherwise try to keep the same order as they were entered
                List<DlcInfo> tmp = new();
                for (int j = 0; j < dlcInfos.Count; j++)
                {
                    if (dlcInfos[j].Type == DlcInfo.DlcType.PSAC)
                    {
                        tmp.Add(dlcInfos[j]);
                    }
                }

                for (int j = 0; j < dlcInfos.Count; j++)
                {
                    if (dlcInfos[j].Type != DlcInfo.DlcType.PSAC)
                    {
                        tmp.Add(dlcInfos[j]);
                    }
                }

                dlcInfos = tmp;

                foreach (var executable in executables)
                {
                    ConsoleUi.LogInfo($"Patching {executable}");
                    await PatchExecutable(executable, outDir, dlcInfos, menuChoice.Equals(choice_dbg_1));
                    ConsoleUi.LogSuccess($"Patching finished for {executable}");
                }

                ConsoleUi.LogInfo($"Output directory: {outDir}");
                ConsoleUi.LogSuccess("Finished patching executables");

                string copyDlcDataIntoFoldersOption = choice6;
                string showDlcInfoOption = "Show DLC required paths";
                string exitOption = "Exit";

                string[] endOptions = [copyDlcDataIntoFoldersOption, showDlcInfoOption, exitOption];

                while (true)
                {
                    var endChoice = AnsiConsole.Prompt(
                        new SelectionPrompt<string>()
                            .Title("Whats next?")
                            .PageSize(10)
                            .AddChoices(
                                endOptions
                            ));

                    if (endChoice == copyDlcDataIntoFoldersOption)
                    {
                        if (dlcInfos.Any(x => x.Type == DlcInfo.DlcType.PSAC && string.IsNullOrWhiteSpace(x.Path)))
                        {
                            ConsoleUi.LogError("Some DLCs dont have a path set");
                            continue;
                        }

                        var updateImage0Path = ConsoleUi.Input("Enter path to update Image0 folder, where dlcXX folders will be created...");
                        if (!Directory.Exists(updateImage0Path))
                        {
                            ConsoleUi.LogError("Path does not exist");
                            continue;
                        }

                        int i = 0;

                        var acDlcs = dlcInfos.Where(x => x.Type == DlcInfo.DlcType.PSAC);

                        var nonAcDlcsCount = dlcInfos.Except(acDlcs).Count();
                        if (nonAcDlcsCount > 0)
                        {
                            ConsoleUi.LogWarning($"Skipping {nonAcDlcsCount} without data dlcs, these dont need folders");
                        }

                        foreach (var dlcInfo in acDlcs)
                        {
                            ConsoleUi.LogInfo($"({i + 1}/{acDlcs.Count()}) Extacting {dlcInfo.EntitlementLabel} to {updateImage0Path}/dlc{i:D2}...");
                            var extractOutDir = Path.Combine(updateImage0Path, $"dlc{i:D2}");
                            await ExtractPkgImage0ToPathAsync(dlcInfo.Path!, extractOutDir);
                            i++;
                        }

                        ConsoleUi.LogSuccess("Finished extracting dlcs");
                        break;
                    }
                    else if (endChoice == showDlcInfoOption)
                    {
                        ConsoleUi.WriteLine("Copy data from dlcs in this order:");

                        var acDlcs = dlcInfos.Where(x => x.Type == DlcInfo.DlcType.PSAC);

                        var nonAcDlcsCount = dlcInfos.Except(acDlcs).Count();
                        if (nonAcDlcsCount > 0)
                        {
                            ConsoleUi.LogWarning($"Skipping {nonAcDlcsCount} without data dlcs, these dont need folders");
                        }

                        int i = 0;
                        foreach (var dlcInfo in acDlcs)
                        {
                            ConsoleUi.WriteLine($"{dlcInfo.EntitlementLabel}/Image0/* -> CUSAxxxxx-patch/Image0/dlc{i:D2}/");
                            i++;
                        }
                    }
                    else if (endChoice == exitOption)
                    {
                        break;
                    }

                }

                Console.WriteLine("Press any key to exit");
                Console.ReadKey();
                exit = true;
            }
            else if (menuChoice == choice2)
            {
                AnsiConsole.WriteLine(new string(Enumerable.Range(start: 0, 16 + 1 + 2 + 1 + 32).Select(x => '-').ToArray()));
                AnsiConsole.WriteLine("entitlementLabel | status | entitlementKey");
                AnsiConsole.WriteLine(new string(Enumerable.Range(start: 0, 16 + 1 + 2 + 1 + 32).Select(x => '-').ToArray()));
                foreach (var dlcInfo in dlcInfos)
                {
                    AnsiConsole.WriteLine(dlcInfo.ToEncodedString());
                }
                AnsiConsole.WriteLine(new string(Enumerable.Range(start: 0, 16 + 1 + 2 + 1 + 32).Select(x => '-').ToArray()));
            }
            else if (menuChoice == choice3)
            {
                dlcInfos.AddRange(ManualDlcInfoInput());
            }
            else if (menuChoice == choice4)
            {
                executables.AddRange(ExecutablePathsInput());
            }
            else if (menuChoice == choice6)
            {
                if (dlcInfos.Any(x => x.Type == DlcInfo.DlcType.PSAC && string.IsNullOrWhiteSpace(x.Path)))
                {
                    ConsoleUi.LogError("Some DLCs dont have a path set");
                    continue;
                }

                var outputDir = ConsoleUi.Input("Enter output folder path... (Each with extra data dlc will be in its own subdirectory named dlcXX (00, 01, 02, ...) in the order you entered them, without extra data dlcs are not counted)");
                if (!Directory.Exists(outputDir))
                {
                    ConsoleUi.LogError("Path does not exist");
                    continue;
                }

                int i = 0;

                var acDlcs = dlcInfos.Where(x => x.Type == DlcInfo.DlcType.PSAC);

                var nonAcDlcsCount = dlcInfos.Except(acDlcs).Count();
                if (nonAcDlcsCount > 0)
                {
                    ConsoleUi.LogWarning($"Skipping {nonAcDlcsCount} without data dlcs, these dont need folders");
                }

                foreach (var dlcInfo in acDlcs)
                {
                    ConsoleUi.LogInfo($"({i + 1}/{acDlcs.Count()}) Extacting {dlcInfo.EntitlementLabel} to {outputDir}/dlc{i:D2}...");
                    var extractOutDir = Path.Combine(outputDir, $"dlc{i:D2}");
                    await ExtractPkgImage0ToPathAsync(dlcInfo.Path!, extractOutDir);
                    i++;
                }

                ConsoleUi.LogSuccess("Finished extracting pkgs");
            }
            else if (menuChoice == choice5)
            {
                exit = true;
            }
        }

    }

    private static readonly string[] importantAppContentSymbols = [
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceAppContentGetAddcontInfoList"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceAppContentGetAddcontInfo"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceAppContentGetEntitlementKey"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceAppContentAddcontMount"),
    ];

    private static readonly string[] importantEntitlementAccessSymbols = [
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceNpEntitlementAccessGetAddcontEntitlementInfo"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceNpEntitlementAccessGetAddcontEntitlementInfoList"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceNpEntitlementAccessGetEntitlementKey"),
    ];

    // https://www.felixcloutier.com/x86/jmp
    private static readonly Code[] possibleJmpCodesInPltFunctionEntry =
    [
        Code.Jmp_rm16,
        Code.Jmp_rm32,
        Code.Jmp_rm64,
        Code.Jmp_ptr1616,
        Code.Jmp_ptr1632,
        Code.Jmp_m1616,
        Code.Jmp_m1632,
        Code.Jmp_m1664,
    ];

    internal static async Task<int> PatchExecutablesNonInteractive(
    IReadOnlyList<string> executables,
    IReadOnlyList<string> dlcPkgs,
    string outputDir,
    bool forceInEboot = false)
    {
        var dlcInfos = dlcPkgs
            .Select(DlcInfo.FromDlcPkg)
            .OrderByDescending(d => d.Type == DlcInfo.DlcType.PSAC)   // PSAC first
            .ToList();

        Directory.CreateDirectory(outputDir);

        foreach (var exe in executables)
        {
            ConsoleUi.LogInfo($"Patching {exe}");
            await PatchExecutable(exe, outputDir, dlcInfos, forceInEboot);
            ConsoleUi.LogSuccess($"Finished {exe}");
        }

        ConsoleUi.LogSuccess($"All patched – output → {outputDir}");
        return 0;
    }

    internal static async Task<int> ExtractDlcsNonInteractive(
        string image0Dir,
        IReadOnlyList<string> dlcPkgs)
    {
        Directory.CreateDirectory(image0Dir);

        int i = 0;
        foreach (var pkg in dlcPkgs)
        {
            var target = Path.Combine(image0Dir, $"dlc{i:D2}");
            await ExtractPkgImage0ToPathAsync(pkg, target);
            i++;
        }

        ConsoleUi.LogSuccess($"Extracted {i} DLCs → {image0Dir}");
        return 0;
    }

    /// <summary>
    /// Convenience wrapper for CLI’s <c>list-dlc</c> command.
    /// </summary>
    internal static DlcInfo? TryParseDlc(string pkg) => DlcInfo.FromDlcPkg(pkg);

    private static async Task PatchExecutable(string inputPath, string outputDir, List<DlcInfo> dlcList, bool forceInEboot = false)
    {
        using var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var br = new BinaryReader(fs);

        var binary = new Ps4ModuleLoader.Ps4Binary(br);
        binary.Process(br);

        List<(ulong offset, byte[] newBytes, string description)> Patches = new();

        bool hasImportantEntitlementAccessRelocations = binary.Relocations.Any(x => x.SYMBOL is not null && importantEntitlementAccessSymbols.Any(y => x.SYMBOL.StartsWith(y)));

        bool hasImportantAppContentSymbols = binary.Relocations.Any(x => x.SYMBOL is not null && importantAppContentSymbols.Any(y => x.SYMBOL.StartsWith(y)));
        if (!hasImportantAppContentSymbols && !hasImportantEntitlementAccessRelocations)
        {
            throw new Exception("This executable doesnt use any functions to get dlc info. This likely means this game loads dlcs in another executable.");
        }

        // check if sceKernelLoadStartModule is in the relocations
        bool hasSceKernelLoadStartModule = binary.Relocations.Any(x => x.SYMBOL is not null && x.SYMBOL.StartsWith(Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceKernelLoadStartModule")));

        // if not check if the nids lengths are the same in libkernel and libSceAppContent
        // if yes we'll replace sceAppContentInitialize with sceKernelLoadStartModule
        // if no and we need to load prx for libSceNpEntitlementAccess also then check sceNpEntitlementAccessInitialize also
        // if no fallback to in eboot handlers
        ulong? sceKernelLoadStartModuleMemOffset = null;
        if (hasSceKernelLoadStartModule)
        {
            sceKernelLoadStartModuleMemOffset = binary.Relocations.FirstOrDefault(x => x.SYMBOL is not null && x.SYMBOL.StartsWith(Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceKernelLoadStartModule")))?.REAL_FUNCTION_ADDRESS;
            ConsoleUi.LogInfo("sceKernelLoadStartModule found in relocations");
        }
        else
        {
            Ps4ModuleLoader.Relocation? libKernelRelocation;
            libKernelRelocation = binary.Relocations.FirstOrDefault(x => x.SYMBOL is not null && LibkernelNids.libkernelNids.Any(y => x.SYMBOL.StartsWith(y)));

            if (libKernelRelocation is null)
            { throw new Exception("libKernelNidLength is null"); }

            if (hasImportantAppContentSymbols)
            {
                var libSceAppContentInitializeRelocation = binary.Relocations.FirstOrDefault(x => x.SYMBOL is not null && x.SYMBOL.StartsWith(Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceAppContentInitialize")));
                if (libSceAppContentInitializeRelocation is null)
                { throw new Exception("sceAppContentInitialize not found"); }

                // its probably okay if libkernel is shorter (with extra null bytes) just not the other way around
                if (libSceAppContentInitializeRelocation.SYMBOL!.Length >= libKernelRelocation.SYMBOL!.Length) // ! -> we're checking for null in the linq query
                {
                    // find symbol cause that contains the file offset
                    var libSceAppContentInitializeNidFileOffset = binary.Symbols.First(x => x.Value!.NID == libSceAppContentInitializeRelocation.SYMBOL).Value!.NID_FILE_ADDRESS;

                    // patch nid to sceKernelLoadStartModule
                    var newBytes = new byte[libSceAppContentInitializeRelocation.SYMBOL.Length];

                    var loadStartModuleNid = Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceKernelLoadStartModule");
                    Encoding.ASCII.GetBytes(loadStartModuleNid, newBytes);
                    // copy from first # to end
                    string libKernelLidMid = libKernelRelocation.SYMBOL.Substring(libKernelRelocation.SYMBOL.IndexOf('#'));
                    Encoding.ASCII.GetBytes(libKernelLidMid, 0, libKernelLidMid.Length, newBytes, loadStartModuleNid.Length);

                    var reencoded = Encoding.ASCII.GetString(newBytes);

                    Patches.Add((libSceAppContentInitializeNidFileOffset, newBytes, "sceAppContentInitialize -> sceKernelLoadStartModule"));
                    sceKernelLoadStartModuleMemOffset = libSceAppContentInitializeRelocation.REAL_FUNCTION_ADDRESS;
                }
            }

            if (sceKernelLoadStartModuleMemOffset is null && hasImportantEntitlementAccessRelocations)
            {
                var libSceNpEntitlementAccessInitializeRelocation = binary.Relocations.FirstOrDefault(x => x.SYMBOL is not null && x.SYMBOL.StartsWith(Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceNpEntitlementAccessInitialize")));
                if (libSceNpEntitlementAccessInitializeRelocation is null)
                { throw new Exception("sceNpEntitlementAccessInitialize not found"); }

                // its probably okay if libkernel is shorter (with extra null bytes) just not the other way around
                if (libSceNpEntitlementAccessInitializeRelocation.SYMBOL!.Length >= libKernelRelocation.SYMBOL!.Length) // ! -> we're checking for null in the linq query
                {
                    // find symbol cause that contains the file offset
                    var libSceNpEntitlementAccessInitializeNidFileOffset = binary.Symbols.First(x => x.Value!.NID == libSceNpEntitlementAccessInitializeRelocation.SYMBOL).Value!.NID_FILE_ADDRESS;

                    // patch nid to sceKernelLoadStartModule
                    var newBytes = new byte[libSceNpEntitlementAccessInitializeRelocation.SYMBOL.Length];

                    var loadStartModuleNid = Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceKernelLoadStartModule");
                    Encoding.ASCII.GetBytes(loadStartModuleNid, newBytes);
                    // copy from first # to end
                    string libKernelLidMid = libKernelRelocation.SYMBOL.Substring(libKernelRelocation.SYMBOL.IndexOf('#'));
                    Encoding.ASCII.GetBytes(libKernelLidMid, 0, libKernelLidMid.Length, newBytes, loadStartModuleNid.Length);

                    var reencoded = Encoding.ASCII.GetString(newBytes);

                    Patches.Add((libSceNpEntitlementAccessInitializeNidFileOffset, newBytes, "sceNpEntitlementAccessInitialize -> sceKernelLoadStartModule"));
                    sceKernelLoadStartModuleMemOffset = libSceNpEntitlementAccessInitializeRelocation.REAL_FUNCTION_ADDRESS;
                }
            }
        }


        // at this point we should have the offset of the sceKernelLoadStartModule 
        // or sceAppContentInitialize patched to sceKernelLoadStartModule
        // if not then we need to fallback to in eboot handlers

        var freeSpaceAtEndOfCodeSegment = GetFreeSpaceAtEndOfCodeSegment(binary, fs);

        if (sceKernelLoadStartModuleMemOffset is not null && !forceInEboot)
        {
            var codeSegment = binary.E_SEGMENTS.First(x => x.GetName() == "CODE");
            // sceKernelLoadStartModuleMemOffset already contains the mem_addr
            var sceKernelLoadStartModuleFileOffset = codeSegment.OFFSET + sceKernelLoadStartModuleMemOffset.Value - codeSegment.MEM_ADDR;
            var ebootPatches = await PrxLoaderStuff.GetAllPatchesForExec(binary, fs, freeSpaceAtEndOfCodeSegment.fileEndAddressOfZeroes - freeSpaceAtEndOfCodeSegment.fileStartAddressOfZeroes, freeSpaceAtEndOfCodeSegment.fileStartAddressOfZeroes, sceKernelLoadStartModuleFileOffset, hasImportantAppContentSymbols, hasImportantEntitlementAccessRelocations);

            Patches.AddRange(ebootPatches);

            var tempPrxPath = Path.Combine(outputDir, "temp_dlcldr.prx");
            PrxLoaderStuff.SaveUnpatchedSignedDlcldrPrxToDisk(tempPrxPath);

            //#if DEBUG
            //            var prxPatches = PrxLoaderStuff.GetAllPatchesForSignedDlcldrPrx(dlcList,debugMode:2);
            //#else
            var prxPatches = PrxLoaderStuff.GetAllPatchesForSignedDlcldrPrx(dlcList);
            //#endif
            using var prxFs = new FileStream(tempPrxPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            {
                foreach (var (offset, newBytes, description) in prxPatches)
                {
                    prxFs.Seek((long)offset, SeekOrigin.Begin);
                    prxFs.Write(newBytes);
                    ConsoleUi.LogInfo($"Applied patch in dlcldr.prx: '{description}' at 0x{offset:X}");
                }
                // even though the using block should take care of this, without explicit close file.move fails bc its locked
                prxFs.Close();
            }

            var realPrxPath = Path.Combine(outputDir, "dlcldr.prx");
            File.Move(tempPrxPath, realPrxPath, true);
        }
        else
        {
            if (hasImportantEntitlementAccessRelocations)
            {
                throw new Exception("Unsupported game. This executable uses libSceNpEntitlementAccess, but the necessary patches for loading prx is not possible and in-executable handlers are not implemented for this libSceNpEntitlementAccess.");
            }

            if (!ConsoleUi.Confirm("Executable doesnt resolve sceKernelLoadStartModule and modding in this function instead of sceAppContentInitialize is not possible for this game. This function is required to load the prx. Do you want to allow fallback to a less safe, more limited method that uses in executable handlers? (fake entitlement key, limited number of dlcs)"))
            {
                throw new Exception("User aborted");
            }

            ConsoleUi.LogWarning("Falling back to in executable method");


            var inEbootPatches = await InExecutableLoaderStuff.GetAllInEbootPatchesForExec(binary, fs, freeSpaceAtEndOfCodeSegment.fileEndAddressOfZeroes - freeSpaceAtEndOfCodeSegment.fileStartAddressOfZeroes, freeSpaceAtEndOfCodeSegment.fileStartAddressOfZeroes, dlcList);
            Patches.AddRange(inEbootPatches);
        }

        // check if we need pht patches
        foreach (var segment in binary.E_SEGMENTS)
        {
            // there are some weird segments that overlaps and messes things up (like INTERP and GNU_EH_FRAME) so restrict to just code for now
            if (segment.GetName() != "CODE")
            { continue; }

            ulong nextSegmentFileStart = binary.E_SEGMENTS.OrderBy(x => x.OFFSET).First(x => x.MEM_ADDR >= segment.MEM_ADDR + segment.MEM_SIZE).OFFSET;

            // list of patches thats offsets are smaller than the next segment start, but bigger than the current segment start
            var allPatchesInSegment = Patches.Where(x => x.offset > segment.OFFSET && x.offset < nextSegmentFileStart);

            var newMaxSegmentSize = allPatchesInSegment.Max(x => x.offset + (ulong)x.newBytes.Length - segment.OFFSET);

            if (newMaxSegmentSize > segment.FILE_SIZE)
            {
                byte[] newFileSizeBytes = new byte[8];
                BinaryPrimitives.WriteUInt64LittleEndian(newFileSizeBytes, newMaxSegmentSize);
                Patches.Add(((ulong)segment.PHT_FILE_SIZE_FIELD_FILE_OFFSET, newFileSizeBytes, $"Increase FILE_SIZE of {segment.GetName()} segment from {segment.FILE_SIZE:X} to {newMaxSegmentSize:X}"));
            }

            if (newMaxSegmentSize > segment.MEM_SIZE)
            {
                byte[] newMemSizeBytes = new byte[8];
                BinaryPrimitives.WriteUInt64LittleEndian(newMemSizeBytes, newMaxSegmentSize);
                Patches.Add(((ulong)segment.PHT_MEM_SIZE_FIELD_FILE_OFFSET, newMemSizeBytes, $"Increase MEM_SIZE of {segment.GetName()} segment from {segment.MEM_SIZE:X} to {newMaxSegmentSize:X}"));
            }
        }

        // apply patches
        var elfOutputPath = Path.Combine(outputDir, Path.GetFileName(inputPath));
        ConsoleUi.LogInfo($"Copying {Path.GetFileName(inputPath)}...");
        File.Copy(inputPath, elfOutputPath, true);

        using var fsOut = new FileStream(elfOutputPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
        {
            foreach (var (offset, newBytes, description) in Patches)
            {
                fsOut.Seek((long)offset, SeekOrigin.Begin);
                fsOut.Write(newBytes);
                ConsoleUi.LogInfo($"Applied patch '{description}' at 0x{offset:X}");
            }
            fsOut.Close();
        }
    }

    private static (int fileStartAddressOfZeroes, int fileEndAddressOfZeroes) GetFreeSpaceAtEndOfCodeSegment(Ps4Binary binary, Stream fileStream)
    {
        var codeSegment = binary.E_SEGMENTS.First(x => x.GetName() == "CODE"); // throws if not found
        ulong codeScanStartRealAddr = codeSegment.OFFSET;
        // start of next segment (-1)
        ulong codeScanEndRealAddr = binary.E_SEGMENTS.OrderBy(x => x.OFFSET).First(x => x.MEM_ADDR >= codeSegment.MEM_ADDR + codeSegment.MEM_SIZE).OFFSET - 1;
        // sanity check
        if (codeScanEndRealAddr + 1 < codeSegment.OFFSET + codeSegment.FILE_SIZE)
        { throw new Exception("Sanity check failed: codeScanEndRealAddr < codeScanStartRealAddr"); }

        ulong freeSpaceAtEndOfCodeSegment = 0;

        // read backwards from the end of the code segment
        fileStream.Seek((long)codeScanEndRealAddr, SeekOrigin.Begin);
        while (fileStream.ReadByte() == 0)
        {
            freeSpaceAtEndOfCodeSegment++;
            // -2 bc readbyte advances the pos
            fileStream.Seek(-2, SeekOrigin.Current);
        }

        if (freeSpaceAtEndOfCodeSegment < 3)
        {
            throw new Exception("No free space found at the end of the code segment");
        }

        ulong fileOffsetOfFreeSpaceStart = codeScanEndRealAddr - freeSpaceAtEndOfCodeSegment + 2;

        return ((int)fileOffsetOfFreeSpaceStart, (int)codeScanEndRealAddr);
    }

    private static List<string> ExecutablePathsInput()
    {
        var lines = ConsoleUi.MultilineInput("Enter executable paths.");
        List<string> executables = new();
        foreach (var line in lines)
        {
            var niceLine = line.Trim().Trim('"');
            if (!File.Exists(niceLine))
            {
                ConsoleUi.LogError($"File not found: {niceLine}");
                continue;
            }

            if (!Path.GetExtension(niceLine).Equals(".elf", StringComparison.OrdinalIgnoreCase))
            {
                ConsoleUi.LogError($"Not an ELF file: {niceLine}");
                continue;
            }

            executables.Add(niceLine);
        }

        ConsoleUi.LogInfo($"Parsed {executables.Count} executables");
        return executables;
    }

    private static List<DlcInfo> ManualDlcInfoInput()
    {
        var lines = ConsoleUi.MultilineInput("Enter dlc infos. Format: (entitlement label)-(status, extra data=04, no extra data=00)-(optional entitlement key, hex encoded)\nEg.:CTNSBUNDLE000000-04-00000000000000000000000000000000 or CTNSBUNDLE000000-04");

        List<DlcInfo> dlcInfos = new();

        foreach (var line in lines)
        {
            try
            {
                var dlcInfo = DlcInfo.FromEncodedString(line);
                dlcInfos.Add(dlcInfo);
            }
            catch (Exception ex)
            {
                ConsoleUi.LogError(ex.Message + $" ({line})");
            }
        }

        ConsoleUi.LogInfo($"Parsed {dlcInfos.Count} DLCs");
        return dlcInfos;
    }

    // https://github.com/OpenOrbis/LibOrbisPkg/blob/594021fdc435409f755a6ae0781b65ec6cec846c/PkgEditor/Views/PkgView.cs#L239
    private static async Task ExtractPkgImage0ToPathAsync(string pkgPath, string outputFolder)
    {
        if (Directory.Exists(outputFolder))
        {
            var choice1 = "Overwrite files in output folder";
            var choice2 = "Skip this pkg";
            var choice3 = "Exit";

            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title($"Output folder '{Path.GetDirectoryName(outputFolder)}' already exists, what do you want to do?")
                    .PageSize(10)
                    .AddChoices(
                        choice1,
                        choice2,
                        choice3
                    ));

            if (choice == choice1)
            {
                // nothing
            }
            else if (choice == choice2)
            {
                ConsoleUi.LogInfo($"Skipping {pkgPath}");
                return;
            }
            else if (choice == choice3)
            {
                throw new Exception("User aborted");
            }
        }
        else
        {
            Directory.CreateDirectory(outputFolder);
        }


        var pkgFile = MemoryMappedFile.CreateFromFile(pkgPath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        Pkg pkg;
        using (var fs = pkgFile.CreateViewStream(0, 0, MemoryMappedFileAccess.Read))
        {
            pkg = new PkgReader(fs).ReadPkg();
        }

        byte[]? ekpfs, data = null, tweak = null;

        if (pkg.CheckPasscode("00000000000000000000000000000000"))
        {
            var passcode = "00000000000000000000000000000000";
            ekpfs = Crypto.ComputeKeys(pkg.Header.content_id, passcode, 1);
        }
        else
        {
            ekpfs = pkg.GetEkpfs();

            if (ekpfs is null)
            {
                throw new Exception("Unable to get ekpfs (not fpkg?)");
            }
        }

        if (!pkg.CheckEkpfs(ekpfs) && (data == null || tweak == null))
        {
            throw new Exception("Invalid ekpfs (not fpkg?)");
        }

        var va = pkgFile.CreateViewAccessor((long)pkg.Header.pfs_image_offset, (long)pkg.Header.pfs_image_size, MemoryMappedFileAccess.Read);
        var outerPfs = new PfsReader(va, pkg.Header.pfs_flags, ekpfs, tweak, data);
        var innerPfsView = new PFSCReader(outerPfs.GetFile("pfs_image.dat").GetView());

        var inner = new PfsReader(innerPfsView);

        var uroot = inner.GetURoot();

        var urootTotalUncompressedSize = uroot.GetAllFiles().Sum(x => x.size);

        var progressBar = new ConsoleUi.FileCopyProgressBar("Extracting dlc pkg", urootTotalUncompressedSize);

        var progressCallback = new Func<long, Task>(progressBar.Increment);
        await ExtractInParallel(uroot.children, outputFolder, progressCallback, 4);

        await progressBar.Update(urootTotalUncompressedSize);

        ConsoleUi.LogSuccess($"Finished extracting pkg {pkgPath} to {outputFolder}");
    }

    // https://github.com/OpenOrbis/LibOrbisPkg/blob/594021fdc435409f755a6ae0781b65ec6cec846c/PkgEditor/Views/FileView.cs#L129C1-L145C6
    // TODO: Parallelize this
    private static async Task SaveTo(IEnumerable<LibOrbisPkg.PFS.PfsReader.Node> nodes, string path, Func<long, Task>? progress = null)
    {
        foreach (var n in nodes)
        {
            if (n is LibOrbisPkg.PFS.PfsReader.File f)
            {
                await f.Save(Path.Combine(path, n.name), n.size != n.compressed_size, progress);
            }
            else if (n is LibOrbisPkg.PFS.PfsReader.Dir d)
            {
                var newPath = Path.Combine(path, d.name);
                Directory.CreateDirectory(newPath);
                await SaveTo(d.children, newPath, progress);
            }
        }
    }

    private static async Task ExtractInParallel(IEnumerable<LibOrbisPkg.PFS.PfsReader.Node> nodes, string outPath, Func<long, Task>? progress = null, int maxConcurrentTasks = -1)
    {
        await Parallel.ForEachAsync(nodes, new ParallelOptions { MaxDegreeOfParallelism = maxConcurrentTasks }, async (n, token) =>
        {
            if (n is LibOrbisPkg.PFS.PfsReader.File f)
            {
                await f.Save(Path.Combine(outPath, n.name), n.size != n.compressed_size, progress);
            }
            else if (n is LibOrbisPkg.PFS.PfsReader.Dir d)
            {
                var newPath = Path.Combine(outPath, d.name);
                Directory.CreateDirectory(newPath);
                await ExtractInParallel(d.children, newPath, progress);
            }
        });
    }


    public static void ListAllExecutablesInPkg(string pkgPath)
    {
        using var pkgFile = MemoryMappedFile.CreateFromFile(pkgPath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        using var fs = pkgFile.CreateViewStream(0, 0, MemoryMappedFileAccess.Read);

        var pkg = new PkgReader(fs).ReadPkg();

        byte[]? ekpfs, data = null, tweak = null;

        if (pkg.CheckPasscode("00000000000000000000000000000000"))
        {
            var passcode = "00000000000000000000000000000000";
            ekpfs = Crypto.ComputeKeys(pkg.Header.content_id, passcode, 1);
        }
        else
        {
            ekpfs = pkg.GetEkpfs();

            if (ekpfs is null)
            {
                throw new Exception("Unable to get ekpfs (not fpkg?)");
            }
        }

        if (!pkg.CheckEkpfs(ekpfs) && (data == null || tweak == null))
        {
            throw new Exception("Invalid ekpfs (not fpkg?)");
        }

        using var va = pkgFile.CreateViewAccessor((long)pkg.Header.pfs_image_offset, (long)pkg.Header.pfs_image_size, MemoryMappedFileAccess.Read);
        var outerPfs = new PfsReader(va, pkg.Header.pfs_flags, ekpfs, tweak, data);
        using var innerPfsView = new PFSCReader(outerPfs.GetFile("pfs_image.dat").GetView());

        var inner = new PfsReader(innerPfsView);

        var uroot = inner.GetURoot();

        ListAllExecutablesInPfsDir(uroot);
        Console.WriteLine("Done");
    }

    private static readonly string[] executableExtensions = [".elf", ".prx", ".sprx", ".bin"];
    private static void ListAllExecutablesInPfsDir(PfsReader.Dir dir)
    {
        foreach (var n in dir.children)
        {
            if (n is LibOrbisPkg.PFS.PfsReader.File f)
            {
                if (executableExtensions.Contains(Path.GetExtension(f.name), StringComparer.InvariantCultureIgnoreCase))
                {
                    Console.WriteLine(f.FullName);
                }
            }
            else if (n is LibOrbisPkg.PFS.PfsReader.Dir d)
            {
                ListAllExecutablesInPfsDir(d);
            }
        }
    }


}
