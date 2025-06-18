function useexternalfunction {
    param (
        [int]$ItemCount = 5
    )

    $dummyData = @()

    for ($i = 0; $i -lt $ItemCount; $i++) {
        $dummyItem = @{
            "id" = $i
            "name" = "Item_$i"
            "value" = (Get-Random -Minimum 1 -Maximum 100)
            "timestamp" = (Get-Date).ToString("o")
            "active" = (Get-Random -Minimum 0 -Maximum 1) -eq 1
        }
        $dummyData += $dummyItem
    }

    return ($dummyData | ConvertTo-Json -Depth 2)
}