<#
    .DESCRIPTION
    Check Lockout Status for User, and unlock if locked.
#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$User,
    [switch]$AllLocations
)

try{
    # Find closest DC
    $DC = (Get-ADDomainController -Discover).hostname

    # Check Lockout Status
    $LockOutStatus = (Get-ADUser -Identity "$User" -Server "$DC" -Properties * | Select-Object LockedOut) | Out-String
        if($LockOutStatus -Match "True"){
            Write-Host "Unlocking $User on $DC. . ." -ForegroundColor Green
            Unlock-ADAccount -Identity "$User" -Server $DC
        }elseif($LockOutStatus -match "False"){
            Write-Host "$User is not locked in $DC!" -ForegroundColor Yellow
    }

    # If All Locations switch is present, unlock in all available DCs
    if($AllLocations.IsPresent){
        $dclist = (Get-ADDomainController -Filter *).hostname
        foreach($DC in $dclist){
                if($LockOutStatus -Match "True"){
                    Write-Host "Unlocking $User  on $DC. . ." -ForegroundColor Green
                    Unlock-ADAccount -Identity "$User" -Server $DC
                }elseif($LockOutStatus -match "False"){
                    Write-Host "$User is not locked in $DC!" -ForegroundColor Yellow
            }
        }
    }
}catch{
    $errormessage = $_.Exception.Message
    Throw $errormessage
}

# SIG # Begin signature block
# MIIPaQYJKoZIhvcNAQcCoIIPWjCCD1YCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUy+RapvUcqLQyO6avhxcNq1Sd
# G6ugggz6MIIF2zCCA8OgAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwXDELMAkGA1UE
# BhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYD
# VQQKDAZBaGlra28xFzAVBgNVBAMMDkFoaWtrbyBSb290IENBMB4XDTIwMDExMjA5
# NDkyNVoXDTMwMDEwOTA5NDkyNVowITEfMB0GA1UEAxMWQWhpa2tvIEludGVybWVk
# aWF0ZSBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAN/yrHTqeyM8
# ISPjuWfIBd+VI253JzV2cBV77YvKVatteJSkLAQeN0XaiVsVpMRLuUooQiwdOyek
# L/pP3Mq5zEsZEz0QShuyR9dhJnbygxCl4/upqSwm5N5rjwkeIccOzk8OSvV0X9s1
# xxs0RQscpVbrcmD3+LT+jx5aSmvwUgTm1Dv4a9Xcc+4hwQjqyWe3P2iNmLJpnFxC
# zx2JZZFwIss3Abh9JYLsoSEe+tcPZulM/aWvho5kxgDPGwqAtFf5ACskbVlzr2iG
# BAhVBSpXdtwWJpKx6Q3Tdkc6v7zLia+aWj/s6DyImHrlkVBwe5qLzFPtWEfgq70w
# o0kxyj6+IOyXtXDpG0JYj1PWZV3QACrwPU+Fi5qnI2TZ82WIC9lKNQPSzL/92B51
# a/kwz4Gi2SjRkief5wrZkkWU4WdbzqaS9xzRSxR95iFPN8/6qyL3IbWRkjlHwfKK
# /5oZ6puBecSgNrN6+D1AbwaobEsQRvNaZuqqCCjJwGCGzuerlC57qD/4Uve9UieR
# qjl3ZsKCtqQ2nVhaIqVD9rSjFOkv5ZTXyq5RPC93906aQYpmaIPt33tC1vqJFIpe
# tHn7Ug2kBqmDWRiMIC3lTDAdX90texPR/WfX9t+HDp1US8d2YUZ6IQ6tNdea3GbV
# OPBjAI7dOpL5jwL1JiQC2n1qj2FAP09xAgMBAAGjgeEwgd4wHQYDVR0OBBYEFMU/
# knFWEzGBOTEXtpEgjuOjXt59MB8GA1UdIwQYMBaAFCNaI9SarKy9vedbHh+1VSaD
# b8WQMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMEIGCCsGAQUF
# BwEBBDYwNDAyBggrBgEFBQcwAoYmaHR0cDovL2NybC5haGlra28ueHl6L0FoaWtr
# b1Jvb3RDQS5jcnQwNAYDVR0fBC0wKzApoCegJYYjaHR0cDovL2NybC5haGlra28u
# eHl6L0FoaWtrb0NSTC5jcmwwDQYJKoZIhvcNAQELBQADggIBAD/V67kqJmRkhRfZ
# unIJ+LYVwp0cIUzLpax/sUfThqlsRIP6MOUdMWMO9usu/45YnQO5RDiOTXxyI9sV
# 71JeFgD1E/qcaoUopEi37zLohXLz9VGuU+m0k+62P1SgvlDHgLx5uXie5bZtNjlg
# 6u7wiO3+O+te8RQwqyT6OLxR6YVkNvAl4YZVA1yew0zjRZNrf0dbrVPD2Buo5/4H
# qkotXi9wTMmN1PH3xQza218joR0AOoB0IBA3wRUHq+mwUza+gqAe9X6wJAd/yRRh
# Ke7KV9BZPhJ7fqnmfw/JpzcOSr1m7riKLuOFG4YCn+i9J1MX3++bEPrRM/p+WVIg
# L+/hiZFO2Q+VKpKeTXP9P8FV1nMlN121KjUk+m8t+ncGsop5q/bbX4KVjUHlV8My
# 9SKiqE7ElxMufr8M1PIPV9ysFT2zS9bb8mHCUUHXJmNfGR4XqJhmyidSQu5tgRel
# Jv5nbrunDrMRYwFowzIqm4Ol0fGWzaGP4DiAKYquFcUQoOJtGIkqMyWUG+ZAWOy7
# JvZhoBtfN1riMkFRLzzRXmIp5L0XkTaWMRnwc1CsFDpYp3iEtLmW51R0iJfOpKbe
# r6BcwXOjbvWEpJuguJEMM3QGKDv1hG2PJw1hqpOKD4rubrr7CNRPTmiBKtCFpjB3
# l5LDS5ZwZsR67BmMT/8+acLFlQ50MIIHFzCCBP+gAwIBAgITMgAAANKxAW/ZRxNk
# MAADAAAA0jANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDExZBaGlra28gSW50ZXJt
# ZWRpYXRlIENBMB4XDTIyMDQwMjA3MTU1NFoXDTI0MDQwMTA3MTU1NFowgbYxEzAR
# BgoJkiaJk/IsZAEZFgN4eXoxFjAUBgoJkiaJk/IsZAEZFgZhaGlra28xGTAXBgNV
# BAsTEFVzZXJzIGFuZCBHcm91cHMxDjAMBgNVBAsTBVVzZXJzMRcwFQYDVQQLEw5T
# dGFuZGFyZCBVc2VyczELMAkGA1UECxMCSFExFTATBgNVBAMTDEtlbm5ldGggUnVh
# bjEfMB0GCSqGSIb3DQEJARYQa3J1YW5AYWhpa2tvLmNvbTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAObdt16kt/ed7admdTHf5qjNO0m98XzE4Aq0Uauj
# wG5X+NRUF6iQ1yfRuvD4T29U870AFVGlyNO+dSzm8F4vMfI27suml8Yniyp9duai
# jcBlHBd87lkxaq8eKED9GhGW4iucS3iOz1avu7B1VtxK3LD7sBrYyoElQbI0dyC3
# nlBgommsnz/ti9qYsROjkHhb+3iDsicg/geTYs6a/Yllm+zskdqzlKLOsiqdM+Dg
# 3rzcPZKHXdryxT5wJX0QvrSfCSD1Y6UBeAGPQYZFWyDl9hWnHXXvutXuc3bVWjIe
# y15w61RE1hVSv3d6bkxUezr5NNcYHO3sZRr/zUbCxgsqHfECAwEAAaOCArAwggKs
# MDsGCSsGAQQBgjcVBwQuMCwGJCsGAQQBgjcVCMz2KsvcAIGxlSiCkaw8h9rNNiOH
# jOkRgY27OQIBZAIBCDATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMC
# B4AwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUF0BTmdcL
# zxlBWnXW4WJxVQMWPYEwHwYDVR0jBBgwFoAUxT+ScVYTMYE5MRe2kSCO46Ne3n0w
# gd0GA1UdHwSB1TCB0jCBz6CBzKCByYaBxmxkYXA6Ly8vQ049QWhpa2tvJTIwSW50
# ZXJtZWRpYXRlJTIwQ0EsQ049dm1pbnRlcm1jYTE5MSxDTj1DRFAsQ049UHVibGlj
# JTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixE
# Qz1haGlra28sREM9eHl6P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
# YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBywYIKwYBBQUHAQEEgb4w
# gbswgbgGCCsGAQUFBzAChoGrbGRhcDovLy9DTj1BaGlra28lMjBJbnRlcm1lZGlh
# dGUlMjBDQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2Vy
# dmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1haGlra28sREM9eHl6P2NBQ2VydGlm
# aWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD0G
# A1UdEQQ2MDSgIAYKKwYBBAGCNxQCA6ASDBBrcnVhbkBhaGlra28uY29tgRBrcnVh
# bkBhaGlra28uY29tMA0GCSqGSIb3DQEBCwUAA4ICAQA6z0Xf1OgmVUkrq0uNlXJm
# HjKLS7NXUeriRBS46odwreF04C64RdTAwTt3wYX/i4yD0yElMWkuplH8VoBFNerB
# i62+DadNJkPRaN9TfokYx7RBi24zlv++JjjVY1Lb+RVjcSfcRokPq6VD9/cfnhpm
# ACgW05e0V+UHufjlPGctF3eM0uhW4RosuWBzPdsrbHymH9f1316flLMfdVzP5ryM
# CTTchVl5+u2snr++HEe1V9EgonLsxHGVx7mj7Aed7DdoS/wzFonF3y2dafagakbn
# USx0cpzKdFjUl7KyQxPgtCZIqoqcPp4MHLvw0DKhUjtfnUGCkk/wu+kl1svgw0ay
# l8Ej0TbnW7zWufAH5k/XIGfjQvobwhMecVsoUQ+iE9kRuiYPfHNJsEGo33k8vE7j
# DRAlUZfE4j6h992Ms/aP/gz1pPPxLB8AAvh+gEgTnzKYFucuIUPOoPp/+OPoyVK8
# /0FJzHii5COoKDkJNJJAN96/r1IURcncKApag0myE2Vpvv8KeVQsdjqk0WdgPgfw
# cd7KeR7gKBodw5FXVRdsu3aseX2t71cDk4LM28nPyCtLiwCdEt9dOylRyYglRwjs
# MHhumhCXgViY4Y5lgAQ1Rqt6ePi9lRH1rTpxFIaFHhFpQN36hbsfjFN6CU3Ls7jf
# xYKoiPf8Gyrfw6YgqqXPNjGCAdkwggHVAgEBMDgwITEfMB0GA1UEAxMWQWhpa2tv
# IEludGVybWVkaWF0ZSBDQQITMgAAANKxAW/ZRxNkMAADAAAA0jAJBgUrDgMCGgUA
# oHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYB
# BAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0B
# CQQxFgQU/oWHeHPLhDKB8Qh2XnCkZut7zBswDQYJKoZIhvcNAQEBBQAEggEA5BzA
# yH8UDR+ZAa03VQzD1LKt1afeHquBD+IwBRbc3RpwTaNRaVEHpZxI7LZ72fPyjhmM
# MmmPKg5AIbuIBGi/mXpNLGzfbA4LkKbmlUwifxAYaBx5Qr3d/ExiH6J9xaneQzRE
# CqVfC2E9SEt26WPgGm7yPUhVdY9BbgYjHv9f9D9ptB+WFrY3E80bnhxXFXsSKv2L
# URe7fMXLYZ01LUV80HUlA7IOkl7F/VWSCgjgSGOKAKuqphq5bRe6ls+hsRs5jPW+
# aqqOq9wmVGcRS00tU7FOzuwGrRZWkqDFAgP+3hQUe+E5X5RIILA2Kubibr9VJd91
# RXW27PfvUb+ytLzo/w==
# SIG # End signature block
