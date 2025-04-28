# winsingleshcleanup or powercleanup
Windows System Cleanup & Optimization Script

Overview
This PowerShell script is a comprehensive system cleanup and performance optimization tool for Windows.
It removes unnecessary files, clears caches, optimizes memory usage, sets high-performance system settings, and improves both CPU and GPU efficiency — all in a single automated run.

The script requires Administrator privileges and is intended for advanced users who want to maximize system performance and free up disk space.

Features
System Cleanup

Clears temp files, old update files, logs, memory dumps, prefetch files

Empties the Recycle Bin

Clears browser caches (Chrome, Edge, Firefox)

Cleans Windows Defender scan history

Removes old installer files, backup files, shadow copies, and event logs

Cleans unnecessary registry entries

Resets Microsoft Store cache and clears delivery optimization files

Clears font cache, error reports, and ETL (Event Tracing for Windows) logs

Flushes DNS cache and clears printer spool

Memory & VRAM Optimization

Flushes system working sets

Clears standby RAM using Sysinternals RAMMap

Optionally kills GPU-intensive background applications

System Performance Tweaks

Enables best performance mode (visual effects settings)

Disables unnecessary services: Superfetch (SysMain), Windows Search, and Hibernation

Sets GPU preference to High Performance for common applications (Chrome, Edge, Blender, Photoshop)

Switches to the High Performance power plan

Displays current GPU usage (NVIDIA only)

Requirements
Windows 10, Windows 11

PowerShell 5.0+

Administrator privileges
Internet connection (only if RAMMap needs to be downloaded)

How to Use
Usually its run with administrator privileges at start automaticall but if it doesn't and buggs out just "Run as Administrator" 
Make sure you right-click and select Run with PowerShell as Administrator.
The script will auto-elevate if not already running with admin rights.

Automatic Execution
Once launched, the script will sequentially execute all cleanup and optimization functions.

Completion
At the end, you will see a confirmation message:
System Cleanup Complete!

Important Notes
Data Loss Warning:
This script permanently deletes cache files, temp files, logs, and other non-essential data. It does not prompt before deletion.

Microsoft Store Cache Reset:
Running wsreset.exe may close your open Store sessions.

Memory Optimization:
RAMMap is automatically downloaded if not already available in your TEMP directory.

NVIDIA GPU Users:
If you have an NVIDIA GPU, nvidia-smi is called to show real-time GPU usage stats.

Disclaimer
This script is provided "as-is" without warranty of any kind.
Use at your own risk. Always make sure to backup important data before running large-scale cleanup or optimization operations.

Author
Developed by: 9Night aka Fatih ULUSOY

Feel free to modify or extend the script to better suit for your system!
