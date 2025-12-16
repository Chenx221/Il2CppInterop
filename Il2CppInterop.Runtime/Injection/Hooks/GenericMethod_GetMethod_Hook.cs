using System;
using System.Linq;
using System.Runtime.InteropServices;
using Il2CppInterop.Common;
using Il2CppInterop.Common.XrefScans;
using Il2CppInterop.Runtime.Runtime;
using Il2CppInterop.Runtime.Startup;
using Microsoft.Extensions.Logging;

namespace Il2CppInterop.Runtime.Injection.Hooks
{
    internal unsafe class GenericMethod_GetMethod_Hook : Hook<GenericMethod_GetMethod_Hook.MethodDelegate>
    {
        public override string TargetMethodName => "GenericMethod::GetMethod";
        public override MethodDelegate GetDetour() => Hook;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate Il2CppMethodInfo* MethodDelegate(Il2CppGenericMethod* gmethod, bool copyMethodPtr);

        private Il2CppMethodInfo* Hook(Il2CppGenericMethod* gmethod, bool copyMethodPtr)
        {
            if (ClassInjector.InflatedMethodFromContextDictionary.TryGetValue((IntPtr)gmethod->methodDefinition, out var methods))
            {
                var instancePointer = gmethod->context.method_inst;
                if (methods.Item2.TryGetValue((IntPtr)instancePointer, out var inflatedMethodPointer))
                    return (Il2CppMethodInfo*)inflatedMethodPointer;

                var typeArguments = new Type[instancePointer->type_argc];
                for (var i = 0; i < instancePointer->type_argc; i++)
                    typeArguments[i] = ClassInjector.SystemTypeFromIl2CppType(instancePointer->type_argv[i]);
                var inflatedMethod = methods.Item1.MakeGenericMethod(typeArguments);
                Logger.Instance.LogTrace("Inflated method: {InflatedMethod}", inflatedMethod.Name);
                inflatedMethodPointer = (IntPtr)ClassInjector.ConvertMethodInfo(inflatedMethod,
                    UnityVersionHandler.Wrap(UnityVersionHandler.Wrap(gmethod->methodDefinition).Class));
                methods.Item2.Add((IntPtr)instancePointer, inflatedMethodPointer);

                return (Il2CppMethodInfo*)inflatedMethodPointer;
            }

            return Original(gmethod, copyMethodPtr);
        }

        private static readonly MemoryUtils.SignatureDefinition[] s_Signatures =
        {
            // Unity 2021.2.5 (x64)
            new MemoryUtils.SignatureDefinition
            {
                pattern = "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x56\x57\x41\x54\x41\x56\x41\x57\x48\x81\xEC\xB0\x00",
                mask = "xxxxxxxxxxxxxxxxxxxxxxx",
                xref = false
            },
            // Unity 6000.0.58f2 (x64) (Suzerain)
            new MemoryUtils.SignatureDefinition
            {
                pattern = "\x40\x53\x48\x83\xEC\x00\x80\x3D\x00\x00\x00\x00\x00\x48\x8B\xD9\x75\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xC6\x05\x00\x00\x00\x00\x00\x48\x8B\x4B\x00\x45\x33\xC0\x33\xD2\xE8",
                mask = "xxxxx?xx?????xxxx?xxx????x????xx?????xxx?xxxxxx",
                xref = false
            },
            new MemoryUtils.SignatureDefinition
            {
                pattern = "\x40\x53\x48\x83\xEC\x00\x80\x3D\x00\x00\x00\x00\x00\x48\x8B\xD9\x75\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC6\x05\x00\x00\x00\x00\x00\x48\x83\x7B\x00\x00\x75\x00\x48\x83\x7B\x00\x00\x74\x00\x80\x7B",
                mask = "xxxxx?xx?????xxxx?xxx????x?????????xx?????xxx??x?xxx??x?xx",
                xref = false
            },
            new MemoryUtils.SignatureDefinition
            {
                pattern = "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x00\x80\x3D\x00\x00\x00\x00\x00\x48\x8B\xF9\x75\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xC6\x05\x00\x00\x00\x00\x00\x48\x8B\x4F\x00\x45\x33\xC0",
                mask = "xxxx?xxxx?xx?????xxxx?xxx????x????xx?????xxx?xxx",
                xref = false
            },

            // 32bit
            new MemoryUtils.SignatureDefinition
            {
                pattern = "\x55\x8B\xEC\x80\x3D\x00\x00\x00\x00\x00\x56\x8B\x75\x00\x75\x00\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x83\xC4\x00\xC6\x05\x00\x00\x00\x00\x00\x6A\x00\x6A",
                mask = "xxxxx?????xxx?x?x????x????x????x????xx?xx?????x?x",
                xref = false
            },
        };

        public override IntPtr FindTargetMethod()
        {
            // On Unity 2021.2+, the 3 parameter shim can be inlined and optimized by the compiler
            // which moves the method we're looking for
            var genericMethodGetMethod = s_Signatures
                .Select(s => MemoryUtils.FindSignatureInModule(InjectorHelpers.Il2CppModule, s))
                .FirstOrDefault(p => p != 0);

            if (genericMethodGetMethod == 0)
            {
                var getVirtualMethodAPI = InjectorHelpers.GetIl2CppExport(nameof(IL2CPP.il2cpp_object_get_virtual_method));
                Logger.Instance.LogTrace("il2cpp_object_get_virtual_method: 0x{GetVirtualMethodApiAddress}", getVirtualMethodAPI.ToInt64().ToString("X2"));

                var getVirtualMethod = XrefScannerLowLevel.JumpTargets(getVirtualMethodAPI).Single();
                Logger.Instance.LogTrace("Object::GetVirtualMethod: 0x{GetVirtualMethodAddress}", getVirtualMethod.ToInt64().ToString("X2"));

                var getVirtualMethodXrefs = XrefScannerLowLevel.JumpTargets(getVirtualMethod).ToArray();

                // If the game is built with IL2CPP Master setting, this will return 0 entries, so we do another xref scan with retn instructions ignored.
                if (getVirtualMethodXrefs.Length == 0)
                {
                    genericMethodGetMethod = XrefScannerLowLevel.JumpTargets(getVirtualMethod, true).Last();
                }
                else
                {
                    // U2021.2.0+, there's additional shim that takes 3 parameters
                    // On U2020.3.41+ there is also a shim, which gets inlined with one added in U2021.2.0+ in release builds
                    if (UnityVersionHandler.HasShimForGetMethod)
                    {
                        var shim = getVirtualMethodXrefs.Last();

                        var shimXrefs = XrefScannerLowLevel.JumpTargets(shim).ToArray();

                        // If the xref count is 1, it probably means the target is after ret
                        if (Il2CppInteropRuntime.Instance.UnityVersion.Major == 2020 && shimXrefs.Length == 1)
                        {
                            shimXrefs = XrefScannerLowLevel.JumpTargets(shim, true).ToArray();
                        }

                        genericMethodGetMethod = shimXrefs.Take(2).Last();
                    }
                    else
                    {
                        genericMethodGetMethod = getVirtualMethodXrefs.Last();
                    }
                }
            }

            return genericMethodGetMethod;
        }
    }
}
