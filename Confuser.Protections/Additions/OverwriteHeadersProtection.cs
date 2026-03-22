using System.Collections.Generic;
using System.Linq;
using Confuser.Core;
using Confuser.Core.Helpers;
using Confuser.Core.Services;
using Confuser.Renamer;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Confuser.Protections.Additions {
	internal class OverwriteHeadersProtection : Protection {
		public const string _Id = "erase headers";
		public const string _FullId = "Ki.OTWPH";

		public override string Name => "PE Headers Protection";
		public override string Description => "This protection overwrites the PE header at runtime.";
		public override string Id => _Id;
		public override string FullId => _FullId;
		public override ProtectionPreset Preset => ProtectionPreset.None;

		protected override void Initialize(ConfuserContext context) { }

		protected override void PopulatePipeline(ProtectionPipeline pipeline) {
			pipeline.InsertPreStage(PipelineStage.EndModule, new OverwritePhase(this));
		}

		class OverwritePhase : ProtectionPhase {
			public OverwritePhase(OverwriteHeadersProtection parent) : base(parent) { }

			public override ProtectionTargets Targets => ProtectionTargets.Modules;
			public override string Name => "Overwriting PE headers";

			protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {
				var rtType = context.Registry.GetService<IRuntimeService>().GetRuntimeType("Confuser.Runtime.OverwritesHeaders");
				var marker = context.Registry.GetService<IMarkerService>();
				var name = context.Registry.GetService<INameService>();

				foreach (ModuleDef module in parameters.Targets.OfType<ModuleDef>()) {
					IEnumerable<IDnlibDef> members = InjectHelper.Inject(rtType, module.GlobalType, module);
					MethodDef cctor = module.GlobalType.FindStaticConstructor();
					var init = (MethodDef)members.Single(method => method.Name == "Initialize");
					cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));

					foreach (IDnlibDef member in members)
						name.MarkHelper(member, marker, (Protection)Parent);
				}
			}
		}
	}
}
