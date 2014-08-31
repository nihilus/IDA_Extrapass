

"IDA_ExtraPass_PlugIn" 
An IDA Pro 5.xx Win32 executable clean up plug-in.
By Sirmabus  V: 2.1

IDA Pro is amazing, IMHO the best disassembler of it's class.
But it's nice to have perfect disassemblies. Certain targets just 
don't disassemble very well.  In particular heavy C++ OOP created programs, 
ones with embedded script systems (with a zillion little bind stubs), etc.
You could be miss something important in your reversing work.

If you didn't know, you can manually clean/fix an IDA Pro database by hand.
Start at the top of the code sections (I.E. ".text") and text search down for
each " dd ", then " db ", make them "unknown" then fix code and data where
needed. You'll find blocks of missed code, messed up arrays/tables that are 
actually code, not data, etc.
Normally this will work easy enough, but try this on a huge 10mb EXE (that could 
be a 100mb+ database!) and watch the tedious hours roll by. After doing this a few 
times, some times taking over eight hours; There had to be a better way..

This is where this plug-in comes in. It simply duplicates the manual steps above
(and a few more) automatically.   It's not perfect, you'll still probably need
to do at least some manual fixing, but it can cut off hours of work.

It does essentially four passes:
1. Convert all stray data to "unknown" (for the following passes).

2. Fixes "align xx" blocks.
   These are internally runs of CCh (int 3), or 90h ('nop') bytes.
   
3. Scans for missing code. Basically tells IDA to convert stray data bytes to code.
   Finds new blocks of codes, or reverts back to data (unfortunately such as in return'less
   exception blocks, or unfortunately some times messes up data/index tables.
   
4. Finds missing/undefined functions. It does this by finding gaps from the end of one
   function to the next.

The plug-in will error on the side of code that can potentially mess up  
data/index tables (kind used with C/C++ "switch()" statements), but the 
sacrifice is for the better IMHO.  The assumption most will want
to find and examine code first, data second.
It's better to run this plug-in just after initial IDA analyze, after the
first save and before you actually start your major work on it.

It's intended for typical Win32 binary executables, so it may, or may not work
on other targets, the odd complied code, etc.
In particular Delphi programs, or any other that tend to mix data and code a lot
in the same section.  In the end you might end up with less functions then when you
started.  To catch this problem, again be sure to save first, then after the plug-in
has run, look in the IDA log window for a negative found function count.


[Install]
Copy the plug-in to your IDA Pro 5.xx "plugins" directory. 
Edit your "plugins.cfg' with a hotkey to run it, etc., as you would install any other
plug-in.  See the IDA docs for more help on this.


[How to run it]
1. Make a backup of your IDA Pro DB.  If there are adverse effects, you can
   restore to your backup.

2. Run the plug-in. Here you have a choice of which passes to run.
   Normally you want them all checked, but if say you are working on a Delphi
   exe you might just want to use the last two options to fix alignment blocks,
   and find missing functions.
   Currently the plug-in will process just the first CODE segment it finds.  
   Usually this will be the ".text" segment.
  
3. If you touch your screen, if you click off the IDA window, IDA will look like
   it locked up. Appears to be a message pump thread starvation issue. 
   Don't know if this can be fixed as it appears other plug-ins have the same problem.
   Some times you can fix it by minimizing then restoring the IDA window.
   If all else fails and you are not sure what is going on, hold down the "Pause/Break" 
   key and the plug-in should abort.
   
4. Let it run and do it's passes..
   It might take a while. On my Core2 Duo 3Ghz, it took about 12 minutes
   to do all passes on a large 11mb (50mb IDA DB) exe.


When it's done and all goes well there should be a plus number of "Found- 
functions:" (a before and after function count), and a lot less gray spots 
on your IDA's navigator scale bar!

For best results, run the plug-in at least two times.

On a particular bad 11mb exe I tested, it recovered ~13,000 missing functions on the 
first, ~1000 on 2nd, and ~900 on 3rd runs!
To make the DB real clean I still had to go through it manually, but the 
time spent is much shorter then the laborious hours..


[Changes]
2.1 - Jan, 18, 2008  - Fixed an obvious issue in the missing function detection.
                       Works much better now finding a lot more functions.
                       When a problem function is found, it's start address is output
                       to the log window for the user to click on and inspect and fix.
		       Added IDA wait dialog.

2.0 - Nov, 25, 2007  - Put in the passes for alignment blocks and finding missing
                       functions.
                       Put a wrapper around "jump" to fix an occasional crash.
                       Converted to VS2005 and added some speed optimizations.
                       Added UI to allow selection of what operations to do.

1.1 - Aug, 28, 20007 - Put WORD scanning back in, and now only attempts 
		       to restore code only in the final (byte) pass. 
		       This ends up  with more code recovered and makes the 
		       whole process faster.
		       

-Sirmabus


Terms of Use
------------
This software is provided "as is", without any guarantee made as to its
suitability or fitness for any particular use. It may contain bugs, so use
this software is at your own risk.  The author(s) no responsibly for any 
damage that may unintentionally be caused through its use.

