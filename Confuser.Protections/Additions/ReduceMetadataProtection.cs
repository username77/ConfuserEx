using System.Linq;
using Confuser.Core;
using dnlib.DotNet;

namespace Confuser.Protections.Additions {
	[BeforeProtection("Ki.ControlFlow")]
	internal class ReduceMetadataProtection : Protection {
		public const string _Id = "reduce md";
		public const string _FullId = "Ki.ReduceMetadata";

		public override string Name => "Reduce Metadata";
		public override string Description => "This optimization removes unnecessary metadata (enum fields, events, properties).";
		public override string Id => _Id;
		public override string FullId => _FullId;
		public override ProtectionPreset Preset => ProtectionPreset.None;

		protected override void Initialize(ConfuserContext context) { }

		protected override void PopulatePipeline(ProtectionPipeline pipeline) {
			pipeline.InsertPreStage(PipelineStage.ProcessModule, new ReduceMetadataPhase(this));
		}

		class ReduceMetadataPhase : ProtectionPhase {
			public ReduceMetadataPhase(ReduceMetadataProtection parent) : base(parent) { }

			public override ProtectionTargets Targets => ProtectionTargets.Methods;
			public override string Name => "Reducing metadata";

			protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {
				foreach (IDnlibDef target in parameters.Targets) {
					if (target is TypeDef typeDef && !IsTypePublic(typeDef)) {
						if (typeDef.IsEnum) {
							int idx = 0;
							while (typeDef.Fields.Count != 1) {
								if (typeDef.Fields[idx].Name != "value__")
									typeDef.Fields.RemoveAt(idx);
								else
									idx++;
							}
						}
					}
					else if (target is EventDef eventDef) {
						if (eventDef.DeclaringType != null)
							eventDef.DeclaringType.Events.Remove(eventDef);
					}
					else if (target is PropertyDef propDef) {
						if (propDef.DeclaringType != null)
							propDef.DeclaringType.Properties.Remove(propDef);
					}
				}
			}

			static bool IsTypePublic(TypeDef type) {
				while (type.IsPublic || type.IsNestedFamily || type.IsNestedFamilyAndAssembly ||
					   type.IsNestedFamilyOrAssembly || type.IsNestedPublic) {
					type = type.DeclaringType;
					if (type == null) return true;
				}
				return false;
			}
		}
	}
}
