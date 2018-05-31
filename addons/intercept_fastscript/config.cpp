class CfgPatches {
	class intercept_fastscript {
		name = "Intercept Fast script interpreter";
		units[] = {};
		weapons[] = {};
		requiredVersion = 1.82;
		requiredAddons[] = {"intercept_core","dedmen_sqf_assembly"};
		author = "Dedmen";
		authors[] = {"Dedmen"};
		url = "https://github.com/dedmen/Intercept_FastScript";
		version = "1.0";
		versionStr = "1.0";
		versionAr[] = {1,0};
	};
};

class Intercept {
    class Dedmen {
        class fastscript {
            pluginName = "dedmen_fastscript"; 
        };
    };
};