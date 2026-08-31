# DWM Hooks
Because AI helped unleashing the RE potential of a guy

## What's this?
I'm a fan of doing silly things with the Windows desktop/windowing system, as you may already see at my [old project](https://github.com/MLXProjects/WPF3DWindowViewer) :)  
This repo is just a sharing of my findings on researching the Windows 10 21H1 DWM by using IDA, OpenCode (along with it's random free models) and half of my brain while I listen to Dubstep music.  
Some of the projects mentioned later on the Motivation section are clearly not "simple", not even for an experienced dev with lots of reverse engineering experience I think, so I'm first learning to walk until I can finally run and do such crazy things.  

## Contents
- `hooks.sln` main solution to build all projects
- `dinject/` DLL injector that targets DWM, requires SYSTEM permissions (I guess due to DWM running in Session 0/1 user)
- `mlxghost/` DLL that hooks into the dwmghost.dll to turn the "not responding" windows red instead of white
- `mlxcore/` DLL that hooks into the dwmcore.dll to write text at the top left of any window (I hope to turn this into a window transform soon) and logs to C:\mlxcore.log for debug

## Motivation
I don't really remember which was the first one, but since ~2015 I've found a bunch of content that made me think "hey that's cool, let's replicate it".  
Due to lack of knowledge and the annoying StackOverflow people, I gave that learning a low priority until something that would answer dumb questions without hating on me was created lol  
Some videos I've found REALLY motivating were:
- [This Windows Longhorn 4015 DCE demo](https://www.youtube.com/watch?v=BkWCS3F99nY&pp=ygUhbG9uZ2hvcm4gNDAxNSBsYWIwNiBkY2UgZGVtbyAyMDAz) was what made me say "okay computer graphics are cool af", basically the trigger that started everything for me.
- [3D framework for the Vista DWM](https://www.youtube.com/watch?v=5_6Fuyu4l_E) exploded my brain like a creeper appearing from behind, and taught me that I was not alone about wanting to get some 3D out ouf the DWM, just like 6 years later.
- [Windows 7 window texture extraction/mirroring](https://www.youtube.com/watch?v=Fpvh16VjrRE) again showed me that I was not alone, just late to the party.
- [3D window manager for XP](https://www.youtube.com/watch?v=Qef6vpEJzJ8) was another mind explosion and showed me the hacky power of PrintWindow(), thanks to that I've made my 3d window viewer mentioned earlier.

## License
I just use Apache 2.0 for everything I make, not sure if it's the right license to use for this repo and really don't care much about that; if you have any concerns (or are MS and want to seriously discuss about this all) please open an issue :D
