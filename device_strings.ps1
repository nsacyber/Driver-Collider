$devList = @()
$logFile = "dev_log.txt"
$sysDrive = Get-ChildItem Env:SystemDrive
$sysRes = Get-ChildItem ($sysDrive.Value + "\") -recurse -Include *.sys

if (Test-Path $logFile)
{
	Remove-Item $logFile -force
}

Foreach($i in $sysRes)
{
	$sigRes = .\sigcheck.exe $i.FullName
	if ($sigRes[6].Contains("Signed") -AND $sigRes[8].Contains("Microsoft"))
	{
		$strRes = .\strings.exe $i
		Foreach ($j in $strRes)
		{
			if ($j.StartsWith("\Device\") -AND !$j.Contains("%"))
			{
				$devList += $j
			}
		}
	}
}

$devList = $devList | sort -unique
Write-Output $devList >> $logFile

