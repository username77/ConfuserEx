using System;
using System.Linq;
using Confuser.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Confuser.Protections.Additions {
	[BeforeProtection("Ki.ControlFlow")]
	internal class MutateConstantsProtection : Protection {
		public const string _Id = "mutate constants";
		public const string _FullId = "Ki.MutateConstants";

		public override string Name => "Mutate Constants";
		public override string Description => "This protection mutates integer constants with sizeof operations.";
		public override string Id => _Id;
		public override string FullId => _FullId;
		public override ProtectionPreset Preset => ProtectionPreset.None;

		protected override void Initialize(ConfuserContext context) { }

		protected override void PopulatePipeline(ProtectionPipeline pipeline) {
			pipeline.InsertPreStage(PipelineStage.ProcessModule, new MutateConstantsPhase(this));
		}

		class MutateConstantsPhase : ProtectionPhase {
			static readonly Random rnd = new Random();

			public MutateConstantsPhase(MutateConstantsProtection parent) : base(parent) { }

			public override ProtectionTargets Targets => ProtectionTargets.Modules;
			public override string Name => "Mutating constants";

			protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {
				foreach (ModuleDef moduleDef in parameters.Targets.OfType<ModuleDef>()) {
					foreach (TypeDef typeDef in moduleDef.Types) {
						foreach (MethodDef methodDef in typeDef.Methods) {
							if (!methodDef.HasBody || !methodDef.Body.HasInstructions)
								continue;

							for (int i = 0; i < methodDef.Body.Instructions.Count; i++) {
								if (!methodDef.Body.Instructions[i].IsLdcI4())
									continue;

								int op = methodDef.Body.Instructions[i].GetLdcI4Value();
								int newvalue = rnd.Next(-100, 10000);
								switch (rnd.Next(1, 4)) {
									case 1:
										methodDef.Body.Instructions[i].Operand = op - newvalue;
										methodDef.Body.Instructions[i].OpCode = OpCodes.Ldc_I4;
										methodDef.Body.Instructions.Insert(i + 1, OpCodes.Ldc_I4.ToInstruction(newvalue));
										methodDef.Body.Instructions.Insert(i + 2, OpCodes.Add.ToInstruction());
										i += 2;
										break;
									case 2:
										methodDef.Body.Instructions[i].Operand = op + newvalue;
										methodDef.Body.Instructions[i].OpCode = OpCodes.Ldc_I4;
										methodDef.Body.Instructions.Insert(i + 1, OpCodes.Ldc_I4.ToInstruction(newvalue));
										methodDef.Body.Instructions.Insert(i + 2, OpCodes.Sub.ToInstruction());
										i += 2;
										break;
									case 3:
										methodDef.Body.Instructions[i].Operand = op ^ newvalue;
										methodDef.Body.Instructions[i].OpCode = OpCodes.Ldc_I4;
										methodDef.Body.Instructions.Insert(i + 1, OpCodes.Ldc_I4.ToInstruction(newvalue));
										methodDef.Body.Instructions.Insert(i + 2, OpCodes.Xor.ToInstruction());
										i += 2;
										break;
								}
							}
						}
					}
				}
			}
		}
	}
}
