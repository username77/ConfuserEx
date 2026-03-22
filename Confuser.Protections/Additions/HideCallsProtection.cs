using System;
using System.Linq;
using Confuser.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Confuser.Protections.Additions {
	internal class HideCallsProtection : Protection {
		public const string _Id = "hide calls";
		public const string _FullId = "Ki.Hcs";

		public override string Name => "Hide Calls Protection";
		public override string Description => "This protection hides method calls via .cctor manipulation.";
		public override string Id => _Id;
		public override string FullId => _FullId;
		public override ProtectionPreset Preset => ProtectionPreset.None;

		protected override void Initialize(ConfuserContext context) { }

		protected override void PopulatePipeline(ProtectionPipeline pipeline) {
			pipeline.InsertPreStage(PipelineStage.ProcessModule, new HideCallsPhase(this));
		}

		class HideCallsPhase : ProtectionPhase {
			public HideCallsPhase(HideCallsProtection parent) : base(parent) { }

			public override ProtectionTargets Targets => ProtectionTargets.Modules;
			public override string Name => "Hide calls injection";

			protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {
				foreach (ModuleDef module in parameters.Targets.OfType<ModuleDef>()) {
					MethodDef method = module.GlobalType.FindStaticConstructor();

					Local sugar = new Local(module.Import(typeof(int)).ToTypeSig());
					Local sugar2 = new Local(module.Import(typeof(bool)).ToTypeSig());

					method.Body.Variables.Add(sugar);
					method.Body.Variables.Add(sugar2);

					Instruction operand = null;
					Instruction instruction = new Instruction(OpCodes.Ret);
					Instruction instruction2 = new Instruction(OpCodes.Ldc_I4_1);

					method.Body.Instructions.Insert(0, new Instruction(OpCodes.Ldc_I4_0));
					method.Body.Instructions.Insert(1, new Instruction(OpCodes.Stloc, sugar));
					method.Body.Instructions.Insert(2, new Instruction(OpCodes.Br, instruction2));

					Instruction instruction3 = new Instruction(OpCodes.Ldloc, sugar);

					method.Body.Instructions.Insert(3, instruction3);
					method.Body.Instructions.Insert(4, new Instruction(OpCodes.Ldc_I4_0));
					method.Body.Instructions.Insert(5, new Instruction(OpCodes.Ceq));
					method.Body.Instructions.Insert(6, new Instruction(OpCodes.Ldc_I4_1));
					method.Body.Instructions.Insert(7, new Instruction(OpCodes.Ceq));
					method.Body.Instructions.Insert(8, new Instruction(OpCodes.Stloc, sugar2));
					method.Body.Instructions.Insert(9, new Instruction(OpCodes.Ldloc, sugar2));
					method.Body.Instructions.Insert(10, new Instruction(OpCodes.Brtrue, method.Body.Instructions[sizeof(decimal) - 6]));
					method.Body.Instructions.Insert(11, new Instruction(OpCodes.Ret));
					method.Body.Instructions.Insert(12, new Instruction(OpCodes.Calli));
					method.Body.Instructions.Insert(13, new Instruction(OpCodes.Sizeof, operand));
					method.Body.Instructions.Insert(method.Body.Instructions.Count, instruction2);
					method.Body.Instructions.Insert(method.Body.Instructions.Count, new Instruction(OpCodes.Stloc, sugar2));
					method.Body.Instructions.Insert(method.Body.Instructions.Count, new Instruction(OpCodes.Br, instruction3));
					method.Body.Instructions.Insert(method.Body.Instructions.Count, instruction);

					ExceptionHandler item2 = new ExceptionHandler(ExceptionHandlerType.Finally) {
						HandlerStart = method.Body.Instructions[10],
						HandlerEnd = method.Body.Instructions[11],
						TryEnd = method.Body.Instructions[14],
						TryStart = method.Body.Instructions[12]
					};

					if (!method.Body.HasExceptionHandlers) {
						method.Body.ExceptionHandlers.Add(item2);
					}

					operand = new Instruction(OpCodes.Br, instruction);
					method.Body.OptimizeBranches();
					method.Body.OptimizeMacros();
				}
			}
		}
	}
}
