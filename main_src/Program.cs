#if DEBUG
#define ENABLE_FORCE_IN_EBOOT_OPTION
#define ENABLE_PRX_LOGGING_OPTION
#define ENABLE_PRX_LOGGING_AND_NOTIFY_OPTION
#define ENABLE_UNIVERSAL_FRAMERATE_PATCH_OPTION
#define ENABLE_CONTINUE_WITHOUT_DLCS_OPTION
#endif

using LibOrbisPkg.PFS;
using LibOrbisPkg.PKG;
using LibOrbisPkg.Util;
using ps4_eboot_dlc_patcher.Ps4ModuleLoader;
using Spectre.Console;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.MemoryMappedFiles;
using System.Text;

namespace ps4_eboot_dlc_patcher;

internal class Program
{
    /// <summary>
    /// if sourcePkg is null then the path is a real os fs path
    /// </summary>
    internal record class ExecutableToPatch(string? sourcePkg, string path);
    private static List<ExecutableToPatch> ExecutablesToPatch = new();

    private static List<DlcInfo> _dlcInfos = new();
    private static IReadOnlyList<DlcInfo> DlcInfos => _dlcInfos.AsReadOnly();
    private static void AddToDlcInfos(DlcInfo dlcInfo)
    {
        var possiblyAlreadExistingItem = _dlcInfos.FirstOrDefault(x => x.EntitlementLabel == dlcInfo.EntitlementLabel);

        if (possiblyAlreadExistingItem is not null)
        {
            _dlcInfos.Remove(possiblyAlreadExistingItem);
        }

        _dlcInfos.Add(dlcInfo);
    }

    private static string menuChoice_patch => $"Patch {ExecutablesToPatch.Count} executable(s) with {DlcInfos.Count} DLC(s)";
    private static string menuChoice_patchForceInExec => $"Patch {ExecutablesToPatch.Count} executable(s) with {DlcInfos.Count} DLC(s) [[FORCE IN EXEC]]";
    private static string menuChoice_patchEnablePrxLogging => $"Patch {ExecutablesToPatch.Count} executable(s) with {DlcInfos.Count} DLC(s) [[ENABLE PRX LOGGING]]";
    private static string menuChoice_patchEnablePrxLoggingAndNotify => $"Patch {ExecutablesToPatch.Count} executable(s) with {DlcInfos.Count} DLC(s) [[ENABLE PRX LOGGING+NOTIFY]]";
    private static string menuChoice_fliprateUnlock => $"Patch {ExecutablesToPatch.Count} executable(s) Universal Fliprate Unlock (pkg src not implemented)";

    private const string menuChoice_printDlcInfos = "Print DLC infos";
    private const string menuChoice_enterMoreArgs = "Enter more args";
    private const string menuChoice_extractDlcs = "Extract w/ extra data dlcs into dlcXX folders";
    private const string menuChoice_exit = "Exit";

    private const string PATCHER_OUT_DIR_NAME = "eboot_patcher_output";
    private static readonly string PatcherOutputDirPath = Path.Combine(AppContext.BaseDirectory, PATCHER_OUT_DIR_NAME);
    static async Task Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (e, a) =>
        {
            ConsoleUi.LogError(((Exception)a.ExceptionObject).Message);
            AnsiConsole.WriteLine("Press any key to exit...");
            Console.ReadKey();
            Environment.Exit(1);
        };

        AnsiConsole.Write(new Panel(new Markup("[b]PS4 EBOOT DLC Patcher[/]").Centered()) { Border = BoxBorder.Rounded }.Expand());

        // if there are any files or folders in PatcherOutputDirPath, ask user if they want to delete it
        if (Directory.Exists(PatcherOutputDirPath) && Directory.EnumerateFileSystemEntries(PatcherOutputDirPath).Any())
        {
            if (ConsoleUi.Confirm($"Output directory '{PatcherOutputDirPath}' not empty, do you want to delete its contents? (Recommended)"))
            {
                Directory.Delete(PatcherOutputDirPath, true);
            }
        }

        if (args.Length > 0)
        {
            ParseInputs(args);
        }

        bool exit = false;
        while (!exit)
        {
            List<string> mainMenuChoices = [menuChoice_patch, menuChoice_printDlcInfos, menuChoice_enterMoreArgs, menuChoice_extractDlcs, menuChoice_exit];

#if ENABLE_FORCE_IN_EBOOT_OPTION
            mainMenuChoices.Add(menuChoice_patchForceInExec);
#endif

#if ENABLE_PRX_LOGGING_OPTION
            mainMenuChoices.Add(menuChoice_patchEnablePrxLogging);
#endif

#if ENABLE_PRX_LOGGING_AND_NOTIFY_OPTION
            mainMenuChoices.Add(menuChoice_patchEnablePrxLoggingAndNotify);
#endif

#if ENABLE_UNIVERSAL_FRAMERATE_PATCH_OPTION
            mainMenuChoices.Add(menuChoice_fliprateUnlock);
#endif

            var menuChoice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("Whats next?")
                    .PageSize(10)
                    .AddChoices(
                    mainMenuChoices
                    ));


            if (menuChoice == menuChoice_patch || menuChoice == menuChoice_patchForceInExec || menuChoice == menuChoice_patchEnablePrxLogging || menuChoice == menuChoice_patchEnablePrxLoggingAndNotify)
            {
                int prxLogLevel = 0;
                if (menuChoice == menuChoice_patchEnablePrxLogging) { prxLogLevel = 1; }
                if (menuChoice == menuChoice_patchEnablePrxLoggingAndNotify) { prxLogLevel = 2; }

                if (!await Patch(menuChoice.Equals(menuChoice_patchForceInExec), prxLogLevel))
                { continue; }

                ConsoleUi.LogSuccess("Done, exiting...");
                exit = true;
            }
            else if (menuChoice == menuChoice_fliprateUnlock) 
            {
                Directory.CreateDirectory(PatcherOutputDirPath);
                foreach (var executable in ExecutablesToPatch)
                {
                    ConsoleUi.LogInfo($"Patching {executable}");
                    PatchUniversalFramerateUnlock(executable, PatcherOutputDirPath);
                }
                ConsoleUi.LogSuccess("Finished patching executables");
            }
            else if (menuChoice == menuChoice_printDlcInfos) { PrintDlcInfos(); }
            else if (menuChoice == menuChoice_enterMoreArgs) { EnterMoreArgs(); }
            else if (menuChoice == menuChoice_extractDlcs) { await ExtractAllAcDlcs(); }
            else if (menuChoice == menuChoice_exit) { exit = true; }
        }

    }

    /// <returns>true if finished/should exit after</returns>
    private static async Task<bool> Patch(bool forceInExec = false, int prxLogLevel = 0)
    {
        if (ExecutablesToPatch.Count == 0)
        {
            ConsoleUi.LogError("No executables to patch");
            return false;
        }

        if (DlcInfos.Count == 0)
        {
            ConsoleUi.LogError("No DLCs infos specified");
#if ENABLE_CONTINUE_WITHOUT_DLCS_OPTION
            if (!ConsoleUi.Confirm("Continue without DLCs?"))
            {
                return false;
            }
#else
            return false;
#endif
        }

        Directory.CreateDirectory(PatcherOutputDirPath);

        _dlcInfos = _dlcInfos.OrderBy(x => x.Type == DlcInfo.DlcType.PSAC ? 0 : 1).ToList();

        foreach (var executable in ExecutablesToPatch)
        {
            ConsoleUi.LogInfo($"Patching {executable}");
            await PatchExecutable(executable, PatcherOutputDirPath, DlcInfos, forceInExec, prxLogLevel);
            ConsoleUi.LogSuccess($"Patching finished for {executable}");
        }

        ConsoleUi.LogInfo($"Output directory: {PatcherOutputDirPath}");
        ConsoleUi.LogSuccess("Finished patching executables");

        string copyDlcDataIntoFoldersOption = menuChoice_extractDlcs;
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
                await ExtractAllAcDlcs();
            }
            else if (endChoice == showDlcInfoOption)
            {
                ConsoleUi.WriteLine("Copy data from dlcs in this order:");

                var acDlcs = DlcInfos.Where(x => x.Type == DlcInfo.DlcType.PSAC).ToArray();

                var nonAcDlcsCount = DlcInfos.Except(acDlcs).Count();
                if (nonAcDlcsCount > 0)
                {
                    ConsoleUi.LogWarning($"Skipping {nonAcDlcsCount} without data dlcs, these dont need folders");
                }

                for (int i = 0; i < acDlcs.Length; i++)
                {
                    var dlcInfo = acDlcs[i];
                    ConsoleUi.WriteLine($"{dlcInfo.EntitlementLabel}/Image0/* -> CUSAxxxxx-patch/Image0/dlc{i:D2}/");
                }
            }
            else if (endChoice == exitOption)
            {
                break;
            }

        }

        return true;
    }

    private static void EnterMoreArgs()
    {
        var inputs = ConsoleUi.MultilineInput("Enter more args... (Items must be separated by new lines. Acceptable inputs are: File (*.elf,*.self,*.prx,*.sprx,*.bin,*.pkg), Folder (finds all supported files [not recursive]), DLC Info (Format: [entitlement label]-[status, extra data=04, no extra data=00]-[optional entitlement key, hex encoded] Eg.:CTNSBUNDLE000000-04-00000000000000000000000000000000 or CTNSBUNDLE000000-04))");
        ParseInputs(inputs);
    }

    private static readonly string[] EXECUTABLE_EXTENSIONS = [".elf", ".self", ".prx", ".sprx", ".bin"];

    private static void ParseInputs(IEnumerable<string> inputs, bool createProgressIndicator = true)
    {
        if (createProgressIndicator)
        {
            Console.WriteLine("Processing inputs...");
        }

        foreach (var raw_input in inputs)
        {
            var input = raw_input.AsSpan().Trim().Trim('"').ToString();
            try
            {
                // if file
                if (File.Exists(input))
                {
                    // if executable
                    if (EXECUTABLE_EXTENSIONS.Contains(Path.GetExtension(input).ToLower()))
                    {
                        // check if it needs to be unsigned and check if it resolves any dlc functions
                        using var fs = File.OpenRead(input);
                        var magicBytes = new byte[4];
                        fs.ReadExactly(magicBytes, 0, 4);
                        fs.Seek(0, SeekOrigin.Begin);
                        if (CheckExecutableResolveDlcFunctions(magicBytes, () => fs))
                        {
                            ExecutablesToPatch.Add(new(null, input));
                            ConsoleUi.LogInfo($"Added executable '{input}' which resolves dlc functions");
                        }
                        else
                        {
                            ConsoleUi.LogWarning($"Ignoring input executable '{input}', it doesnt resolve any dlc functions");
#if ENABLE_CONTINUE_WITHOUT_DLCS_OPTION
                            if (ConsoleUi.Confirm("Do you want to add it anyway?"))
                            {
                                ExecutablesToPatch.Add(new(null, input));
                            }
#endif
                        }

                    }
                    else if (Path.GetExtension(input).Equals(".pkg", StringComparison.InvariantCultureIgnoreCase))
                    {
                        // check for any executables in the pkg
                        // i still havent seen a game have executables in a dlc pkg, but lets check anyway, its quick
                        // if dlc add to dlc list
                        bool foundExec = false;
                        try
                        {
                            var uroot = GetPkgUroot(input);
                            var potentialExecs = GetPotentialExecutablesInPkgDir(uroot);

                            if (potentialExecs.Count() != 0)
                            {
                                ConsoleUi.LogInfo($"Checking pkg '{input}' for executables that resolve dlc functions...");
                            }

                            foreach (var potentialExec in potentialExecs)
                            {
                                if (CheckExecutableResolveDlcFunctions(potentialExec))
                                {
                                    ExecutablesToPatch.Add(new(input, potentialExec.FullName));
                                    foundExec = true;
                                    ConsoleUi.LogSuccess($"Found executable '{potentialExec.FullNameImage0}' in pkg '{input}' which resolves dlc functions");
                                }
#if DEBUG
                                else
                                {
                                    ConsoleUi.LogWarning($"Executable '{potentialExec.FullNameImage0}' in pkg '{input}' doesnt resolve any dlc functions");
                                }
#endif
                            }
                        }
                        catch (FormatException)
                        {
                            // ignore
                            // no files in an additional license pkg
                        }

                        try
                        {
                            var dlcInfo = DlcInfo.FromDlcPkg(input); // throws if not a dlc pkg or is invalid
                            AddToDlcInfos(dlcInfo);
                            ConsoleUi.LogInfo($"Parsed dlc pkg '{input}'");
                        }
                        catch (Exception)
                        {
                            // not (valid) dlc pkg
                            if (!foundExec)
                            {
                                ConsoleUi.LogWarning($"Ignoring input file '{input}', not a dlc and no executables found using dlc function.");
                            }
                        }
                    }
                    else
                    {
                        ConsoleUi.LogWarning($"Ignoring input file '{input}'");
                    }
                }
                else if (Directory.Exists(input))
                {
                    // call parseinputs on all pkg and executable files
                    var files = Directory.GetFiles(input).AsEnumerable();
                    files = files.Where(x => EXECUTABLE_EXTENSIONS.Contains(Path.GetExtension(x).ToLower()) || Path.GetExtension(x).Equals(".pkg", StringComparison.InvariantCultureIgnoreCase));
                    ParseInputs(files, false);
                }
                else
                {
                    try
                    {
                        // FromEncodedString throws if not valid
                        var dlcInfo = DlcInfo.FromEncodedString(input);
                        AddToDlcInfos(dlcInfo);
                        ConsoleUi.LogInfo($"Added dlc '{dlcInfo.EntitlementLabel}'");
                    }
                    catch (Exception)
                    {
                        ConsoleUi.LogWarning($"Ignoring unknown input '{input}'");
                    }
                }
            }
            catch (Exception ex)
            {
                ConsoleUi.LogError(ex.Message);
                if (!ConsoleUi.Confirm($"An error occured while processing input '{input}', continue (ignore this file)?"))
                {
#if DEBUG
                    throw;
#endif
                    throw new Exception("User aborted");
                }


            }
        }

    }

    private static bool CheckExecutableResolveDlcFunctions(PfsReader.File pfsFile)
    {
        var view = pfsFile.GetView();

        if (pfsFile.size != pfsFile.compressed_size)
        {
            view = new PFSCReader(view);
        }

        byte[] magicBytes = new byte[4];
        view.Read(0, magicBytes, 0, 4);

        MemoryStream? originalFileMs = null;
        var res = CheckExecutableResolveDlcFunctions(magicBytes, () =>
        {
            originalFileMs = new MemoryStream();
            pfsFile.Save(originalFileMs, pfsFile.size != pfsFile.compressed_size).GetAwaiter().GetResult();
            originalFileMs.Seek(0, SeekOrigin.Begin);

            return originalFileMs;
        });
        originalFileMs?.Dispose();
        return res;
    }

    /// <param name="getStream">To avoid needing to read in the whole file into memory if the magic is wrong</param>
    private static bool CheckExecutableResolveDlcFunctions(byte[] magicBytes, Func<Stream> getStream)
    {
        var execType = SelfUtil.SelfUtil.GetFileType(magicBytes);

        if (execType == SelfUtil.SelfUtil.FileType.Ps5Self)
        {
            // unreachable bc this is a ps4 pkg
            ConsoleUi.LogError("PS5 executables are not supported");
            return false;
        }
        else if (execType == SelfUtil.SelfUtil.FileType.Unknown)
        {
            return false;
        }

        var originalFileMs = getStream();
        originalFileMs.Seek(0, SeekOrigin.Begin);
        using var ms2 = new MemoryStream();

        BinaryReader? br = null;

        try
        {
            // if executable is signed then unsign it
            if (execType == SelfUtil.SelfUtil.FileType.Ps4Self)
            {
                var selfutil = new SelfUtil.SelfUtil(originalFileMs);
                selfutil.SaveToELF(ms2);
                ms2.Seek(0, SeekOrigin.Begin);
                br = new BinaryReader(ms2);
            }
            else if (execType == SelfUtil.SelfUtil.FileType.Uelf)
            {
                br = new BinaryReader(originalFileMs);
            }
            else
            {
                throw new UnreachableException(); // in case new exec types are added
            }

            var binary = new Ps4Binary(br);
            binary.Process(br);

            bool hasImportantEntitlementAccessRelocations = binary.Relocations.Any(x => x.SYMBOL is not null && importantEntitlementAccessSymbols.Any(y => x.SYMBOL.StartsWith(y)));

            bool hasImportantAppContentSymbols = binary.Relocations.Any(x => x.SYMBOL is not null && importantAppContentSymbols.Any(y => x.SYMBOL.StartsWith(y)));
            return hasImportantAppContentSymbols || hasImportantEntitlementAccessRelocations;
        }
        finally
        {
            br?.Dispose();
        }

    }

    private static void PrintDlcInfos()
    {
        AnsiConsole.WriteLine(new string(Enumerable.Range(start: 0, 16 + 1 + 2 + 1 + 32).Select(x => '-').ToArray()));
        AnsiConsole.WriteLine("entitlementLabel | status | entitlementKey");
        AnsiConsole.WriteLine(new string(Enumerable.Range(start: 0, 16 + 1 + 2 + 1 + 32).Select(x => '-').ToArray()));
        foreach (var dlcInfo in DlcInfos)
        {
            AnsiConsole.WriteLine(dlcInfo.ToEncodedString());
        }
        AnsiConsole.WriteLine(new string(Enumerable.Range(start: 0, 16 + 1 + 2 + 1 + 32).Select(x => '-').ToArray()));
    }

    /// <returns>true if should exit after</returns>
    private static async Task<bool> ExtractAllAcDlcs()
    {
        if (DlcInfos.Any(x => x.Type == DlcInfo.DlcType.PSAC && string.IsNullOrWhiteSpace(x.Path)))
        {
            if (!ConsoleUi.Confirm("Some with extra data DLCs dont have a pkg associated so nothing can be extracted, for these empty folders will be created. Continue?"))
            { return false; }
        }

        var updateImage0Path = ConsoleUi.Input("Enter path to update Image0 folder, where dlcXX folders will be created...");
        if (!Directory.Exists(updateImage0Path))
        {
            ConsoleUi.LogError("Directory does not exist");
            return false;
        }

        var acDlcs = DlcInfos.Where(x => x.Type == DlcInfo.DlcType.PSAC).ToArray();

        var nonAcDlcsCount = DlcInfos.Except(acDlcs).Count();
        if (nonAcDlcsCount > 0)
        {
            ConsoleUi.LogWarning($"Skipping {nonAcDlcsCount} without data dlcs, these dont need folders");
        }

        for (int i = 0; i < acDlcs.Length; i++)
        {
            var dlcInfo = acDlcs[i];
            ConsoleUi.LogInfo($"({i + 1}/{acDlcs.Count()}) Extracting {dlcInfo.EntitlementLabel} to {updateImage0Path}/dlc{i:D2}...");
            var extractOutDir = Path.Combine(updateImage0Path, $"dlc{i:D2}");
            if (string.IsNullOrWhiteSpace(dlcInfo.Path))
            {
                Directory.CreateDirectory(extractOutDir);
                ConsoleUi.LogSuccess($"Created empty folder for {dlcInfo.EntitlementLabel}");
            }
            else
            {
                await ExtractPkgImage0ToPathAsync(dlcInfo.Path!, extractOutDir);
            }
        }

        ConsoleUi.LogSuccess("Finished extracting dlcs");
        return true;
    }

    // Credits to illusion0001 for this method
    private static void PatchUniversalFramerateUnlock(ExecutableToPatch inputExecInfo, string outputDir)
    {
        if (inputExecInfo.sourcePkg is not null)
        {
            throw new NotImplementedException("Execs from pkgs not implemented for fliprate unlock");
        }

        using var fs = new FileStream(inputExecInfo.path, FileMode.Open, FileAccess.Read, FileShare.Read);

        var magicBytes = new byte[4];

        fs.Read(magicBytes, 0, 4);
        fs.Seek(0, SeekOrigin.Begin);

        var execType = SelfUtil.SelfUtil.GetFileType(magicBytes);

        MemoryStream? unsignedExecStream = null; // not used if input file is already unsigned
        BinaryReader? br = null;

        try
        {
            if (execType == SelfUtil.SelfUtil.FileType.Ps4Self)
            {
                var selfutil = new SelfUtil.SelfUtil(fs);
                unsignedExecStream = new MemoryStream();
                selfutil.SaveToELF(unsignedExecStream);
                unsignedExecStream.Seek(0, SeekOrigin.Begin);

                br = new BinaryReader(unsignedExecStream);
            }
            else if (execType == SelfUtil.SelfUtil.FileType.Uelf)
            {
                br = new BinaryReader(fs);
            }
            else
            {
                throw new ArgumentException("Not a valid executable");
            }

            var binary = new Ps4ModuleLoader.Ps4Binary(br);
            binary.Process(br);

            string setFlipRateNid = Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceVideoOutSetFlipRate");

            var setFlipRateRelocation = binary.Relocations.FirstOrDefault(x => x.SYMBOL is not null && x.SYMBOL.StartsWith(setFlipRateNid));
            if (setFlipRateRelocation is null)
            {
                throw new Exception("sceVideoOutSetFlipRate not found in relocations");
            }

            List<(ulong offset, byte[] newBytes, string description)> Patches = new();

            // patch with xor eax, eax ret
            Patches.Add((setFlipRateRelocation.REAL_FUNCTION_ADDRESS_FILE(binary), new byte[] { 0x31, 0xC0, 0xC3 }, "Universal Framerate Unlock"));


            // save copy of unsigned file
            br.BaseStream.Seek(0, SeekOrigin.Begin);
            string outPath = Path.Combine(outputDir, Path.GetFileName(inputExecInfo.path));
            using var outFs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None);
            br.BaseStream.CopyTo(outFs);

            // apply patches
            foreach (var (offset, newBytes, description) in Patches)
            {
                outFs.Seek((long)offset, SeekOrigin.Begin);
                outFs.Write(newBytes, 0, newBytes.Length);
            }

            ConsoleUi.LogSuccess($"Saved patched '{Path.GetFileName(inputExecInfo.path)}' with Universal Framerate Unlock to '{outPath}'");
        }
        finally
        {
            br?.Dispose();
            unsignedExecStream?.Dispose();
        }
    }

    private static readonly string[] importantAppContentSymbols = [
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceAppContentGetAddcontInfoList"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceAppContentGetAddcontInfo"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceAppContentGetEntitlementKey"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceAppContentAddcontMount"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceAppContentAppParamGetInt"),
    ];

    private static readonly string[] importantEntitlementAccessSymbols = [
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceNpEntitlementAccessGetAddcontEntitlementInfo"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceNpEntitlementAccessGetAddcontEntitlementInfoList"),
        Ps4ModuleLoader.Utils.CalculateNidForSymbol("sceNpEntitlementAccessGetEntitlementKey"),
    ];

    private static async Task PatchExecutable(ExecutableToPatch inputExecInfo, string outputDir, IReadOnlyList<DlcInfo> dlcList, bool forceInEboot = false, int prxLogLevel = 0)
    {
        // oof this is kind of a mess
        MemoryStream? unsignedExecStream = null; // not used if input file is a real file that is already unsigned
        FileStream? alreadyUnsignedExecStream = null;
        BinaryReader? br = null;

        try
        {
            if (inputExecInfo.sourcePkg is not null)
            {
                var uroot = GetPkgUroot(inputExecInfo.sourcePkg);
                var targetExecFile = uroot.GetAllFiles().FirstOrDefault(x => x.FullName == inputExecInfo.path);

                if (targetExecFile is null)
                {
                    throw new UnreachableException($"Couldnt find executable '{inputExecInfo.path}' in pkg '{inputExecInfo.sourcePkg}'");
                }

                var view = targetExecFile.GetView();

                if (targetExecFile.size != targetExecFile.compressed_size)
                {
                    view = new PFSCReader(view);
                }

                // check if it needs to be unsigned
                byte[] magicBytes = new byte[4];

                view.Read(0, magicBytes, 0, 4);

                var elfType = SelfUtil.SelfUtil.GetFileType(magicBytes);

                if (elfType == SelfUtil.SelfUtil.FileType.Ps4Self)
                {
                    using var tempMs = new MemoryStream();

                    await targetExecFile.Save(tempMs, targetExecFile.size != targetExecFile.compressed_size);

                    tempMs.Seek(0, SeekOrigin.Begin);
                    var selfutil = new SelfUtil.SelfUtil(tempMs);

                    unsignedExecStream = new MemoryStream();
                    selfutil.SaveToELF(unsignedExecStream);
                    unsignedExecStream.Seek(0, SeekOrigin.Begin);

                    br = new BinaryReader(unsignedExecStream);
                }
                else if (elfType == SelfUtil.SelfUtil.FileType.Uelf)
                {
                    unsignedExecStream = new MemoryStream();
                    await targetExecFile.Save(unsignedExecStream, targetExecFile.size != targetExecFile.compressed_size);

                    br = new BinaryReader(unsignedExecStream);
                }
                else
                {
                    throw new ArgumentException("Not a valid executable");
                }
            }
            else // input is real file
            {
                using var tempFs = new FileStream(inputExecInfo.path, FileMode.Open, FileAccess.Read, FileShare.Read);
                var magicBytes = new byte[4];
                tempFs.Read(magicBytes, 0, 4);
                tempFs.Seek(0, SeekOrigin.Begin);

                var execType = SelfUtil.SelfUtil.GetFileType(magicBytes);

                if (execType == SelfUtil.SelfUtil.FileType.Ps4Self)
                {
                    using var tempMs = new MemoryStream();
                    var selfutil = new SelfUtil.SelfUtil(tempFs);
                    unsignedExecStream = new MemoryStream();
                    selfutil.SaveToELF(unsignedExecStream);
                    unsignedExecStream.Seek(0, SeekOrigin.Begin);

                    br = new BinaryReader(unsignedExecStream);

                }
                else if (execType == SelfUtil.SelfUtil.FileType.Uelf)
                {
                    alreadyUnsignedExecStream = new FileStream(inputExecInfo.path, FileMode.Open, FileAccess.Read, FileShare.Read);
                    br = new BinaryReader(alreadyUnsignedExecStream);
                }
                else
                {
                    throw new ArgumentException("Not a valid executable");
                }
            }


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
                try
                {
                    Ps4ModuleLoader.Relocation? libKernelRelocation;
                    libKernelRelocation = binary.Relocations.FirstOrDefault(x => x.SYMBOL is not null && LibkernelNids.libkernelNids.Any(y => x.SYMBOL.StartsWith(y)));

                    if (libKernelRelocation is null)
                    { throw new Exception("libKernelNidLength is null"); }

                    List<(ulong offset, byte[] newBytes, string description)> temp_patches = new();
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

                            temp_patches.Add((libSceAppContentInitializeNidFileOffset, newBytes, "sceAppContentInitialize -> sceKernelLoadStartModule"));
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

                            temp_patches.Add((libSceNpEntitlementAccessInitializeNidFileOffset, newBytes, "sceNpEntitlementAccessInitialize -> sceKernelLoadStartModule"));
                            sceKernelLoadStartModuleMemOffset = libSceNpEntitlementAccessInitializeRelocation.REAL_FUNCTION_ADDRESS;
                        }
                    }
                    Patches.AddRange(temp_patches);
                }
                catch (System.Exception ex)
                {
                    ConsoleUi.LogWarning($"Prx loading is not possible: {ex.Message}");
                    sceKernelLoadStartModuleMemOffset = null;
                }
            }


            // at this point we should have the offset of the sceKernelLoadStartModule 
            // or sceAppContentInitialize patched to sceKernelLoadStartModule
            // if not then we need to fallback to in eboot handlers

            var freeSpaceAtEndOfCodeSegment = GetFreeSpaceAtEndOfCodeSegment(binary, br.BaseStream);

            if (sceKernelLoadStartModuleMemOffset is not null && !forceInEboot)
            {
                var codeSegment = binary.E_SEGMENTS.First(x => x.GetName() == "CODE");
                // sceKernelLoadStartModuleMemOffset already contains the mem_addr
                var sceKernelLoadStartModuleFileOffset = codeSegment.OFFSET + sceKernelLoadStartModuleMemOffset.Value - codeSegment.MEM_ADDR;
                var ebootPatches = await PrxLoaderStuff.GetAllPatchesForExec(binary, br.BaseStream, freeSpaceAtEndOfCodeSegment.fileEndAddressOfZeroes - freeSpaceAtEndOfCodeSegment.fileStartAddressOfZeroes, freeSpaceAtEndOfCodeSegment.fileStartAddressOfZeroes, sceKernelLoadStartModuleFileOffset, hasImportantAppContentSymbols, hasImportantEntitlementAccessRelocations);

                Patches.AddRange(ebootPatches);

                var tempPrxPath = Path.Combine(outputDir, "temp_dlcldr.prx");
                PrxLoaderStuff.SaveUnpatchedSignedDlcldrPrxToDisk(tempPrxPath);

                var prxPatches = PrxLoaderStuff.GetAllPatchesForSignedDlcldrPrx(dlcList, prxLogLevel);

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


                var inEbootPatches = await InExecutableLoaderStuff.GetAllInEbootPatchesForExec(binary, br.BaseStream, freeSpaceAtEndOfCodeSegment.fileEndAddressOfZeroes - freeSpaceAtEndOfCodeSegment.fileStartAddressOfZeroes, freeSpaceAtEndOfCodeSegment.fileStartAddressOfZeroes, dlcList);
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

            // copy file and apply patches
            string elfOutputPath;
            if (inputExecInfo.sourcePkg is not null)
            {
                string subdirName = GetPkgImage0OutputDirName(inputExecInfo.sourcePkg);

                string urootlessInPkgPath = inputExecInfo.path.AsSpan().TrimStart('/').TrimStart('\\').TrimStart("uroot").TrimStart('/').TrimStart('\\').ToString();

                elfOutputPath = Path.Combine(outputDir, subdirName, urootlessInPkgPath);
            }
            else
            {
                elfOutputPath = Path.Combine(outputDir, Path.GetFileName(inputExecInfo.path));
            }

            if (File.Exists(elfOutputPath))
            {
                if (!ConsoleUi.Confirm($"File '{elfOutputPath}' already exists, overwrite?"))
                {
                    throw new Exception("User aborted");
                }
            }

            // create needed directories recursively
            var path = Path.GetDirectoryName(elfOutputPath);
            if (path is null)
            {
                throw new Exception("Path.GetDirectoryName returned null");
            }
            
            Directory.CreateDirectory(path);

            ConsoleUi.LogInfo($"Saving {Path.GetFileName(inputExecInfo.path)}...");

            using var fsOut = new FileStream(elfOutputPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
            {
                br.BaseStream.Seek(0, SeekOrigin.Begin);
                await br.BaseStream.CopyToAsync(fsOut);
                foreach (var (offset, newBytes, description) in Patches)
                {
                    fsOut.Seek((long)offset, SeekOrigin.Begin);
                    fsOut.Write(newBytes);
                    ConsoleUi.LogInfo($"Applied patch '{description}' at 0x{offset:X}");
                }
            }
        }
        finally
        {
            unsignedExecStream?.Dispose();
            alreadyUnsignedExecStream?.Dispose();
            br?.Dispose();
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

        var uroot = GetPkgUroot(pkgPath);

        var urootTotalUncompressedSize = uroot.GetAllFiles().Sum(x => x.size);

        var progressBar = new ConsoleUi.FileCopyProgressBar("Extracting dlc pkg", urootTotalUncompressedSize);

        var progressCallback = new Func<long, Task>(progressBar.Increment);
        await ExtractInParallel(uroot.children, outputFolder, progressCallback, 4);

        await progressBar.Update(urootTotalUncompressedSize);

        ConsoleUi.LogSuccess($"Finished extracting pkg {pkgPath} to {outputFolder}");
    }

    private static string GetPkgImage0OutputDirName(string pkgPath)
    {
        var pkgFile = MemoryMappedFile.CreateFromFile(pkgPath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        Pkg pkg;
        using (var fs = pkgFile.CreateViewStream(0, 0, MemoryMappedFileAccess.Read))
        {
            pkg = new PkgReader(fs).ReadPkg();
        }

        var category = pkg.ParamSfo.ParamSfo["CATEGORY"].ToString();
        string friendlyContentType = category switch
        {
            "gp" => "Update",
            "gd" => "Base",
            "ac" => "Dlc",
            _ => throw new Exception("Unsupported pkg type")
        };

        return $"{pkg.Header.content_id}-{friendlyContentType}-Image0";
    }

    /// <exception cref="FormatException">if pkg doesnt have a pfs (additional license only)</exception>
    private static PfsReader.Dir GetPkgUroot(string pkgPath)
    {
        var pkgFile = MemoryMappedFile.CreateFromFile(pkgPath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        Pkg pkg;
        using (var fs = pkgFile.CreateViewStream(0, 0, MemoryMappedFileAccess.Read))
        {
            pkg = new PkgReader(fs).ReadPkg();
        }

        if (pkg.Header.content_type == ContentType.AL)
        {
            throw new FormatException("Pkg does have a pfs image");
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

        //outPkg = pkg;

        return inner.GetURoot();
    }

    private static IEnumerable<PfsReader.File> GetPotentialExecutablesInPkgDir(PfsReader.Dir dir)
    {
        foreach (var n in dir.children)
        {
            if (n is PfsReader.File f)
            {
                if (EXECUTABLE_EXTENSIONS.Contains(Path.GetExtension(f.name).ToLower()))
                {
                    yield return f;
                }
            }
            else if (n is PfsReader.Dir d)
            {
                if (d.name == "sce_module" || d.name == "sce_sys")
                {
                    continue;
                }
                foreach (var f2 in GetPotentialExecutablesInPkgDir(d))
                {
                    yield return f2;
                }
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

}
