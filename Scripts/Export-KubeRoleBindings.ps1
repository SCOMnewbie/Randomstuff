
$roleMapping = @()
$results = $p |ConvertFrom-Json -Depth 99 | Select-object -ExpandProperty items | Select-Object -Property `
    @{label = 'rolebindingType';expression = { $_.kind } },
    @{label = 'rolebindingName';expression = { $_.metadata.name } },
    @{label = 'roleName';expression = { $_.roleRef.name } },
    @{label = 'subjectKind';expression = { $_.subjects.kind } },
    @{label = 'subjectName';expression = { $_.subjects.name } }

foreach($result in $results){

    if($result.subjectName.count -gt 1){
        #More than one subject
        for($i=0; $i -le $result.subjectName.count; $i++){
            $myObject = [PSCustomObject]@{
                rolebindingType     = $result.rolebindingType
                rolebindingName     = $result.rolebindingName
                roleName     = $result.roleName
                subjectKind     = $result.subjectKind[$i]
                subjectName     = $result.subjectName[$i]
            }
            $roleMapping += $myObject
        }
    }
    else{
        #Only one subject
        $roleMapping += $result
    }
}

$roleMapping
#TODO: update is as a function