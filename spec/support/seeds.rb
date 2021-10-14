# frozen_string_literal: true
# rubocop:disable Layout/LineLength
# rubocop:disable Metrics/MethodLength
def seeds
  {
    tpm: {
      origin: 'https://5fa54deb.ngrok.io',
      credential_creation_options: {
        challenge: 'RzPxs+DAAg5rSQtlCrClt8s/RZMuVtf2xfkW8LlVUcs='
      },
      authenticator_attestation_response: {
        attestation_object: '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',
        client_data_json: 'ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlJ6UHhzLURBQWc1clNRdGxDckNsdDhzX1JaTXVWdGYyeGZrVzhMbFZVY3MiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vNWZhNTRkZWIubmdyb2suaW8iLA0KCSJ0b2tlbkJpbmRpbmciIDogDQoJew0KCQkic3RhdHVzIiA6ICJzdXBwb3J0ZWQiDQoJfQ0KfQ=='
      }
    },
    security_key_direct: {
      credential_creation_options: {
        challenge: 'F2jm+R5P/aK+VXJNAs7GhUfd8D4ymIKcgv6mmdvUzuw='
      },
      authenticator_attestation_response: {
        attestation_object: 'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAKmahJEF9gQ3EfWCUGIetNOyChxKgfPMcm2t97vg+yQkAiA9+gWsIVvM8UzG4Zx6miqPpOE6va/ikr2s5JkVQ3S0dWN4NWOBWQFqMIIBZjCCAQugAwIBAgIJANeVSb0aZxdPMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDEZUIEZJRE8gMDIwMDAgFw0xNzA2MjAwMDAwMDBaGA8yMDQwMDUwMTAwMDAwMFowHzEdMBsGA1UEAwwURlQgRklETyAwNDMwMDEzM0M4QTgwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATAzkwrAKYxGoVk3nrr+9vQZMZcfTCF5IqIW5bRGtng6JonnixY3AeTZPfb/Rso1mg2lNVb6p1PbRy37ulJLgUBozYwNDAdBgNVHQ4EFgQU9LZKaMM06QG44jxuZuaGbDGTH10wEwYLKwYBBAGC5RwCAQEEBAMCBDAwCgYIKoZIzj0EAwIDSQAwRgIhAMGUGKbJb2yoaZustVZ3X8BnxgjzncUIImqhASs+nJxnAiEAjdMkQsf7x2mbPasyOJOPoaIC8AMjz7rpXspBRTWkhtloYXV0aERhdGFY5EmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAGAnQmgK9fqO6GyjOGVX1nBX85Gk5mI+kqURsbIIllIhmMEe2FH6fyHwulFi/vOygBo7EhRutk//JvwjfToylYKlC8zJPzytWDOR8LS3m+cfJipGkijlwo2yPJHgF0nJvgKlAQIDJiABIVggk+pSofda627UgESjbV7uHFaEiIIicMPWkx7vBR/ErQMiWCC68L6IPQcv6CxYJZnohL1l8O7vydwBWZZeFTudPCRpgg==',
        client_data_json: 'eyJjaGFsbGVuZ2UiOiJGMmptLVI1UF9hSy1WWEpOQXM3R2hVZmQ4RDR5bUlLY2d2Nm1tZHZVenV3Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9'
      }
    },
    security_key_packed_self: {
      credential_creation_options: {
        challenge: '11CzaFXezx7YszNaYE3pag=='
      },
      authenticator_attestation_response: {
        attestation_object: 'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhAJc6Qi6mOud2D0e9T3tQpboLxE2siYhIbVeVLshPiKzeAiAsdfEJjga0O2L5VhbqLg6kQEoHvLbq8/ko4MRdUi6bcGhhdXRoRGF0YVj6SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFW7bk1wAAAAAAAAAAAAAAAAAAAAAAdgAezFgAiz7YPD6hRcRNhQ9uY/dLBawkl3mVweop75ZgTOoLy0o4mvXkp/ONBc2KHcV3n8vXr8SXEiWm0a4/xnX+oqE6jlbpSAxxwAAOS2/KwQDDhieLe9lYYvnflU1HBXO9M7eNFewdKNyAn2/fcuUJ2m/e9eOlAQIDJiABIVggHODJJzEPq1BsCkbguTwIOfP/VdYf+7j3SjP2h0mjbEciWCBQLw970904u+6tLdjzE8ppuXz0Kdn93cpKjo8gXCgv8A==',
        client_data_json: 'eyJjaGFsbGVuZ2UiOiIxMUN6YUZYZXp4N1lzek5hWUUzcGFnIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDoxMzAxMCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ=='
      }
    },
    security_key_packed_x5c: {
      credential_creation_options: {
        challenge: 'd7vCJu3yGKUgolBiWbzT9Z2vt94GOSJh7p9I9HdTHEY='
      },
      authenticator_attestation_response: {
        attestation_object: 'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgSQ0NpOp6iiJ5zaOVi45o7G2qBBbIoI98/OXMjsN0rHoCIH+jbu+pvM/yzYHwSQWKE2feOxwQzsiDyJnxn2giUchlY3g1Y4FZAsIwggK+MIIBpqADAgECAgR0hv3CMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBvMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxOTU1MDAzODQyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElV3zrfckfTF17/2cxPMaToeOuuGBCVZhUPs4iy5fZSe/V0CapYGlDQrFLxhEXAoTVIoTU8ik5ZpwTlI7wE3r7aNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQ+KAR84wKTRWABhcRH57cfTAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAxXEiA5ppSfjhmib1p/Qqob0nrnk6FRUFVb6rQCzoAih3cAflsdvZoNhqR4jLIEKecYwdMm256RusdtdhcREifhop2Q9IqXIYuwD8D5YSL44B9es1V+OGuHuITrHOrSyDj+9UmjLB7h4AnHR9L4OXdrHNNOliXvU1zun81fqIIyZ2KTSkC5gl6AFxNyQTcChgSDgr30Az8lpoohuWxsWHz7cvGd6Z41/tTA5zNoYa+NLpTMZUjQ51/2Upw8jBiG5PEzkJo0xdNlDvGrj/JN8LeQ9a0TiEVPfhQkl+VkGIuvEbg6xjGQfD+fm8qCamykHcZ9i5hNaGQMqITwJi3KDzuaGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XY0EAAAAt+KAR84wKTRWABhcRH57cfQBAM0uzSYY2jMTu+ofrNa6sAwTLAMrQ5jfvIwddjgVY4wfzBljHvKLC+4iKgpdUDt3dmzJtLSTECCRJYaWIKvpenaUBAgMmIAEhWCBeJ7nIauwxLoXgazc4Zd/uj0vc+pXy7Mr2iHQrVhJITCJYIGG+peCzzf6zUbmx8fi2TTt/UBFJLV5UitNjHSe9HO8g',
        client_data_json: 'eyJjaGFsbGVuZ2UiOiJkN3ZDSnUzeUdLVWdvbEJpV2J6VDlaMnZ0OTRHT1NKaDdwOUk5SGRUSEVZIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0='
      }
    },
    android_safetynet_direct: {
      credential_creation_options: {
        challenge: 'K6ND8440Xz5BXoLoAUuv/f+x2DVnEDAsPuIE0BcFOGk='
      },
      authenticator_attestation_response: {
        attestation_object: 'o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDE3Nzg1MDM3aHJlc3BvbnNlWRS9ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHYTJwRFEwSkljV2RCZDBsQ1FXZEpVVkpZY205T01GcFBaRkpyUWtGQlFVRkJRVkIxYm5wQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFSkRUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZSV1ZOUW5kSFFURlZSVU5vVFZaU01qbDJXako0YkVsR1VubGtXRTR3U1VaT2JHTnVXbkJaTWxaNlRWSk5kMFZSV1VSV1VWRkVSWGR3U0ZaR1RXZFJNRVZuVFZVNGVFMUNORmhFVkVVMFRWUkJlRTFFUVROTlZHc3dUbFp2V0VSVVJUVk5WRUYzVDFSQk0wMVVhekJPVm05M1lrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaEZla0ZTUW1kT1ZrSkJaMVJEYTA1b1lrZHNiV0l6U25WaFYwVjRSbXBCVlVKblRsWkNRV05VUkZVeGRtUlhOVEJaVjJ4MVNVWmFjRnBZWTNoRmVrRlNRbWRPVmtKQmIxUkRhMlIyWWpKa2MxcFRRazFVUlUxNFIzcEJXa0puVGxaQ1FVMVVSVzFHTUdSSFZucGtRelZvWW0xU2VXSXliR3RNYlU1MllsUkRRMEZUU1hkRVVWbEtTMjlhU1doMlkwNUJVVVZDUWxGQlJHZG5SVkJCUkVORFFWRnZRMmRuUlVKQlRtcFlhM293WlVzeFUwVTBiU3N2UnpWM1QyOHJXRWRUUlVOeWNXUnVPRGh6UTNCU04yWnpNVFJtU3pCU2FETmFRMWxhVEVaSWNVSnJOa0Z0V2xaM01rczVSa2N3VHpseVVsQmxVVVJKVmxKNVJUTXdVWFZ1VXpsMVowaEROR1ZuT1c5MmRrOXRLMUZrV2pKd09UTllhSHAxYmxGRmFGVlhXRU40UVVSSlJVZEtTek5UTW1GQlpucGxPVGxRVEZNeU9XaE1ZMUYxV1ZoSVJHRkROMDlhY1U1dWIzTnBUMGRwWm5NNGRqRnFhVFpJTDNob2JIUkRXbVV5YkVvck4wZDFkSHBsZUV0d2VIWndSUzkwV2xObVlsazVNRFZ4VTJ4Q2FEbG1jR293TVRWamFtNVJSbXRWYzBGVmQyMUxWa0ZWZFdWVmVqUjBTMk5HU3pSd1pYWk9UR0Y0UlVGc0swOXJhV3hOZEVsWlJHRmpSRFZ1Wld3MGVFcHBlWE0wTVROb1lXZHhWekJYYUdnMVJsQXpPV2hIYXpsRkwwSjNVVlJxWVhwVGVFZGtkbGd3YlRaNFJsbG9hQzh5VmsxNVdtcFVORXQ2VUVwRlEwRjNSVUZCWVU5RFFXeG5kMmRuU2xWTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlJtOUVRVlJDWjA1V1NGTlZSVVJFUVV0Q1oyZHlRbWRGUmtKUlkwUkJWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDTUVkQk1WVmtSR2RSVjBKQ1VYRkNVWGRIVjI5S1FtRXhiMVJMY1hWd2J6UlhObmhVTm1veVJFRm1RbWRPVmtoVFRVVkhSRUZYWjBKVFdUQm1hSFZGVDNaUWJTdDRaMjU0YVZGSE5rUnlabEZ1T1V0NlFtdENaMmR5UW1kRlJrSlJZMEpCVVZKWlRVWlpkMHAzV1VsTGQxbENRbEZWU0UxQlIwZEhNbWd3WkVoQk5reDVPWFpaTTA1M1RHNUNjbUZUTlc1aU1qbHVUREprTUdONlJuWk5WRUZ5UW1kbmNrSm5SVVpDVVdOM1FXOVpabUZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VERKa2VtTnFTWFpTTVZKVVRWVTRlRXh0VG5sa1JFRmtRbWRPVmtoU1JVVkdha0ZWWjJoS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDBsUldVUldVakJuUWtKdmQwZEVRVWxDWjFwdVoxRjNRa0ZuU1hkRVFWbExTM2RaUWtKQlNGZGxVVWxHUVhwQmRrSm5UbFpJVWpoRlMwUkJiVTFEVTJkSmNVRm5hR2cxYjJSSVVuZFBhVGgyV1ROS2MweHVRbkpoVXpWdVlqSTVia3d3WkZWVmVrWlFUVk0xYW1OdGQzZG5aMFZGUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpKU0RGQ1NVaDVRVkJCUVdSM1EydDFVVzFSZEVKb1dVWkpaVGRGTmt4TldqTkJTMUJFVjFsQ1VHdGlNemRxYW1RNE1FOTVRVE5qUlVGQlFVRlhXbVJFTTFCTVFVRkJSVUYzUWtsTlJWbERTVkZEVTFwRFYyVk1Tblp6YVZaWE5rTm5LMmRxTHpsM1dWUktVbnAxTkVocGNXVTBaVmswWXk5dGVYcHFaMGxvUVV4VFlta3ZWR2g2WTNweGRHbHFNMlJyTTNaaVRHTkpWek5NYkRKQ01HODNOVWRSWkdoTmFXZGlRbWRCU0ZWQlZtaFJSMjFwTDFoM2RYcFVPV1ZIT1ZKTVNTdDRNRm95ZFdKNVdrVldla0UzTlZOWlZtUmhTakJPTUVGQlFVWnRXRkU1ZWpWQlFVRkNRVTFCVW1wQ1JVRnBRbU5EZDBFNWFqZE9WRWRZVURJM09IbzBhSEl2ZFVOSWFVRkdUSGx2UTNFeVN6QXJlVXhTZDBwVlltZEpaMlk0WjBocWRuQjNNbTFDTVVWVGFuRXlUMll6UVRCQlJVRjNRMnR1UTJGRlMwWlZlVm8zWmk5UmRFbDNSRkZaU2t0dldrbG9kbU5PUVZGRlRFSlJRVVJuWjBWQ1FVazVibFJtVWt0SlYyZDBiRmRzTTNkQ1REVTFSVlJXTm10aGVuTndhRmN4ZVVGak5VUjFiVFpZVHpReGExcDZkMG8yTVhkS2JXUlNVbFF2VlhORFNYa3hTMFYwTW1Nd1JXcG5iRzVLUTBZeVpXRjNZMFZYYkV4UldUSllVRXg1Um1wclYxRk9ZbE5vUWpGcE5GY3lUbEpIZWxCb2RETnRNV0kwT1doaWMzUjFXRTAyZEZnMVEzbEZTRzVVYURoQ2IyMDBMMWRzUm1sb2VtaG5iamd4Ukd4a2IyZDZMMHN5VlhkTk5sTTJRMEl2VTBWNGEybFdabllyZW1KS01ISnFkbWM1TkVGc1pHcFZabFYzYTBrNVZrNU5ha1ZRTldVNGVXUkNNMjlNYkRabmJIQkRaVVkxWkdkbVUxZzBWVGw0TXpWdmFpOUpTV1F6VlVVdlpGQndZaTl4WjBkMmMydG1aR1Y2ZEcxVmRHVXZTMU50Y21sM1kyZFZWMWRsV0daVVlra3plbk5wYTNkYVltdHdiVkpaUzIxcVVHMW9kalJ5YkdsNlIwTkhkRGhRYmpod2NUaE5Na3RFWmk5UU0ydFdiM1F6WlRFNFVUMGlMQ0pOU1VsRlUycERRMEY2UzJkQmQwbENRV2RKVGtGbFR6QnRjVWRPYVhGdFFrcFhiRkYxUkVGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFrMU5VMEYzU0dkWlJGWlJVVXhGZUdSSVlrYzVhVmxYZUZSaFYyUjFTVVpLZG1JelVXZFJNRVZuVEZOQ1UwMXFSVlJOUWtWSFFURlZSVU5vVFV0U01uaDJXVzFHYzFVeWJHNWlha1ZVVFVKRlIwRXhWVVZCZUUxTFVqSjRkbGx0Um5OVk1teHVZbXBCWlVaM01IaE9la0V5VFZSVmQwMUVRWGRPUkVwaFJuY3dlVTFVUlhsTlZGVjNUVVJCZDA1RVNtRk5SVWw0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFTTkhkSVFWbEVWbEZSUzBWNFZraGlNamx1WWtkVloxWklTakZqTTFGblZUSldlV1J0YkdwYVdFMTRSWHBCVWtKblRsWkNRVTFVUTJ0a1ZWVjVRa1JSVTBGNFZIcEZkMmRuUldsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVUpFZDBGM1oyZEZTMEZ2U1VKQlVVUlJSMDA1UmpGSmRrNHdOWHByVVU4NUszUk9NWEJKVW5aS2VucDVUMVJJVnpWRWVrVmFhRVF5WlZCRGJuWlZRVEJSYXpJNFJtZEpRMlpMY1VNNVJXdHpRelJVTW1aWFFsbHJMMnBEWmtNelVqTldXazFrVXk5a1RqUmFTME5GVUZwU2NrRjZSSE5wUzFWRWVsSnliVUpDU2pWM2RXUm5lbTVrU1UxWlkweGxMMUpIUjBac05YbFBSRWxMWjJwRmRpOVRTa2d2VlV3clpFVmhiSFJPTVRGQ2JYTkxLMlZSYlUxR0t5dEJZM2hIVG1oeU5UbHhUUzg1YVd3M01Va3laRTQ0UmtkbVkyUmtkM1ZoWldvMFlsaG9jREJNWTFGQ1ltcDRUV05KTjBwUU1HRk5NMVEwU1N0RWMyRjRiVXRHYzJKcWVtRlVUa001ZFhwd1JteG5UMGxuTjNKU01qVjRiM2x1VlhoMk9IWk9iV3R4TjNwa1VFZElXR3Q0VjFrM2IwYzVhaXRLYTFKNVFrRkNhemRZY2twbWIzVmpRbHBGY1VaS1NsTlFhemRZUVRCTVMxY3dXVE42Tlc5Nk1rUXdZekYwU2t0M1NFRm5UVUpCUVVkcVoyZEZlazFKU1VKTWVrRlBRbWRPVmtoUk9FSkJaamhGUWtGTlEwRlpXWGRJVVZsRVZsSXdiRUpDV1hkR1FWbEpTM2RaUWtKUlZVaEJkMFZIUTBOelIwRlJWVVpDZDAxRFRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaFJXVVJXVWpCUFFrSlpSVVpLYWxJclJ6UlJOamdyWWpkSFEyWkhTa0ZpYjA5ME9VTm1NSEpOUWpoSFFURlZaRWwzVVZsTlFtRkJSa3AyYVVJeFpHNUlRamRCWVdkaVpWZGlVMkZNWkM5alIxbFpkVTFFVlVkRFEzTkhRVkZWUmtKM1JVSkNRMnQzU25wQmJFSm5aM0pDWjBWR1FsRmpkMEZaV1ZwaFNGSXdZMFJ2ZGt3eU9XcGpNMEYxWTBkMGNFeHRaSFppTW1OMldqTk9lVTFxUVhsQ1owNVdTRkk0UlV0NlFYQk5RMlZuU21GQmFtaHBSbTlrU0ZKM1QyazRkbGt6U25OTWJrSnlZVk0xYm1JeU9XNU1NbVI2WTJwSmRsb3pUbmxOYVRWcVkyMTNkMUIzV1VSV1VqQm5Ra1JuZDA1cVFUQkNaMXB1WjFGM1FrRm5TWGRMYWtGdlFtZG5ja0puUlVaQ1VXTkRRVkpaWTJGSVVqQmpTRTAyVEhrNWQyRXlhM1ZhTWpsMlduazVlVnBZUW5aak1td3dZak5LTlV4NlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGSGIwRXJUbTV1TnpoNU5uQlNhbVE1V0d4UlYwNWhOMGhVWjJsYUwzSXpVazVIYTIxVmJWbElVRkZ4TmxOamRHazVVRVZoYW5aM1VsUXlhVmRVU0ZGeU1ESm1aWE54VDNGQ1dUSkZWRlYzWjFwUksyeHNkRzlPUm5ab2MwODVkSFpDUTA5SllYcHdjM2RYUXpsaFNqbDRhblUwZEZkRVVVZzRUbFpWTmxsYVdpOVlkR1ZFVTBkVk9WbDZTbkZRYWxrNGNUTk5SSGh5ZW0xeFpYQkNRMlkxYnpodGR5OTNTalJoTWtjMmVIcFZjalpHWWpaVU9FMWpSRTh5TWxCTVVrdzJkVE5OTkZSNmN6TkJNazB4YWpaaWVXdEtXV2s0ZDFkSlVtUkJka3RNVjFwMUwyRjRRbFppZWxsdGNXMTNhMjAxZWt4VFJGYzFia2xCU21KRlRFTlJRMXAzVFVnMU5uUXlSSFp4YjJaNGN6WkNRbU5EUmtsYVZWTndlSFUyZURaMFpEQldOMU4yU2tORGIzTnBjbE50U1dGMGFpODVaRk5UVmtSUmFXSmxkRGh4THpkVlN6UjJORnBWVGpnd1lYUnVXbm94ZVdjOVBTSmRmUS5leUp1YjI1alpTSTZJbmwzUkdoMFFrSTFSMFZsYWs1VlluTXlTbkpHUzJsVk1sSlViRnBRV1ZoWk0xWTBjVUpNV1VrMUsyTTlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFOakkxTVRZeE1EazVOemdzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbWx1WlM5cGEyZzVWRUZrYTFCUldVTndaMkZTY0RsdFRTOXVjV2swVlU0MGMwcGxaWFUzWVdwWlZFMDlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC5MOWxWUWdtWUF6ZzJSVGdHM3RKejZpOXBZU25BTUYyOHR4azB1bXdoWW9YWExCblVtcFRnc1duRWpXSjdFRnM0SnhKa0ptQjZHQTZ0MXliZjJLcVp0VGIwcTVDZVVnWVVsRldlalV2Z2hIS0VfZjJqSWRCdG5YZmNOamhfcTFMOUl6QW91VkdaYXpZZFNsYjMxTnZjWWR5Wnl1d1NITWNFMnR0N0xYYkVDT0xDUXVKUVFfcDIwa3VIQjhjX0U4RkdudDFkR2FlUzZLRDBVQUxXQmExd1J3UThPSElTczI2VGZLU1VlQmdfbGtSeW50d2MyMWtkdnNYMjA1QkZZS1lhY0JhelVDN2ppN09lUmpyQ2ZlVXNHN1R2Q1FIZGRjaU1xeURVOHBLQmxXOEFWVU1lLWVRWEMwNGtqSXUtYWRmUTN3TXhyRklWU25Ebmd3bE9aVmZzOEFoYXV0aERhdGFYxRqbUaddjvie9x59A9Bsvgs+6EEHtVLvmRJFzOxjyy1rRQAAAAC5P9lh8uZGL7EiggAiR954AEEBmFu1jh2ovcS41Lb0zurtpKX9C/1Whvz4+m1jlju0j5joHx3JrjBMeqLvop9C0j+asBi+thkQiDSK9XeypGgTi6UBAgMmIAEhWCBxXU6T25ZDHfJhaZVwYUBpKVp2QgVaUrI5lsheAyshvCJYIEv4jfo+6wIfcM1TXGdC8VhSMFug42qTa+Fil9HucAjx',
        client_data_json: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSzZORDg0NDBYejVCWG9Mb0FVdXZfZi14MkRWbkVEQXNQdUlFMEJjRk9HayIsIm9yaWdpbiI6Imh0dHBzOlwvXC83ZjQxYWM0NS5uZ3Jvay5pbyIsImFuZHJvaWRQYWNrYWdlTmFtZSI6ImNvbS5hbmRyb2lkLmNocm9tZSJ9'
      }
    },
    android_key_direct: {
      origin: 'http://localhost:4567',
      credential_creation_options: {
        challenge: '-Yv-EqbaIvRX_dMrbMAD_-5ZihaWBNa9r0VBQtEfPCc'
      },
      authenticator_attestation_response: {
        "attestation_object": 'o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiAzQUycv5aoxWgk71qQ3HVdDuNdXA8-xwMfXwOgKPab6QIgMoS1a6ilLVoRZ6Dd9oro0oYt83AT_HMPvVLzOq_QQa1jeDVjglkDHDCCAxgwggK9oAMCAQICAQEwCgYIKoZIzj0EAwIwgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwIBcNNzAwMjAxMDAwMDAwWhgPMjA5OTAxMzEyMzU5NTlaMCkxJzAlBgNVBAMMHkZBS0UgQW5kcm9pZCBLZXlzdG9yZSBLZXkgRkFLRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCNX8kv82Kviqq58cUSQLerq2rY5okerKGDxuXWGzWJjfavzAwMKsFvhmYfDomiTyqtrFb7USyK_aagD2HoZEu2jggEWMIIBEjALBgNVHQ8EBAMCB4AwgeEGCisGAQQB1nkCAREEgdIwgc8CAQIKAQACAQEKAQAEIHihcjf9tv8l9QJdxilFWzctg_FuL-qHjKZrfcqLCAUmBAAwab-FPQgCBgFe0-PPoL-FRVkEVzBVMS8wLQQoY29tLmFuZHJvaWQua2V5c3RvcmUuYW5kcm9pZGtleXN0b3JlZGVtbwIBATEiBCB0z8tQdIj1KRCFkcelBZGfMncy-8HYA1Jq6pgABtLYmDAyoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBAr-FPgMCAQC_hT8CBQAwHwYDVR0jBBgwFoAUo9KqLO8NjPIkAtUctGC8v2pbJBQwCgYIKoZIzj0EAwIDSQAwRgIhALxV9BrdRWmvixsyDLf83C8FqAYHJH15e3DqamXyQUC9AiEArBX3yZEi8kKHR7Ek2Hpnr5rcI7-j5kJH4M6jN1j_NaxZAxgwggMUMIICuqADAgECAgECMAoGCCqGSM49BAMCMIHcMT0wOwYDVQQDDDRGQUtFIEFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdCBGQUtFMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xOTA0MjUwNTQ5MzJaFw00NjA5MTAwNTQ5MzJaMIHkMUUwQwYDVQQDDDxGQUtFIEFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlIEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq1BhK2JNF7vDtRsESTsFSQuMH4udvPN5st7coHxSode2DdMhddwrft28JtsI1V-G9nG2lNwwTaSiioxOA6b1x6NjMGEwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0OBBYEFKPSqizvDYzyJALVHLRgvL9qWyQUMB8GA1UdIwQYMBaAFFKaGzLgVqrNUQ_vX4A3BovykSMdMAoGCCqGSM49BAMCA0gAMEUCIQCxby5AL7R6zm05jfD9PsiyE-Pej_8HkhBGwerwiVkofQIgbvlDqKwni3BeFosThvROS4tp13uLjNqupmyhpJZfLvloYXV0aERhdGFYpEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAGNVDktUqkdAn5qVGrdsEwExACCJyLXRivxPIVFJglV2nG1OMttTfk2lZOrDfFO_rkAHZ6UBAgMmIAEhWCAjV_JL_Nir4qqufHFEkC3q6tq2OaJHqyhg8bl1hs1iYyJYIH2r8wMDCrBb4ZmHw6Jok8qraxW-1Esiv2moA9h6GRLt',
        "client_data_json": 'eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjQ1NjciLCJjaGFsbGVuZ2UiOiItWXYtRXFiYUl2UlhfZE1yYk1BRF8tNVppaGFXQk5hOXIwVkJRdEVmUENjIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9'
      }
    },
    u2f_migration: {
      stored_credential: {
        certificate: 'MIIBNDCB26ADAgECAgp2ubKB51u9YwjcMAoGCCqGSM49BAMCMBUxEzARBgNVBAMTClUyRiBJc3N1ZXIwGhcLMDAwMTAxMDAwMFoXCzAwMDEwMTAwMDBaMBUxEzARBgNVBAMTClUyRiBEZXZpY2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQfqziP5Gobu7FmIoFH0WCaD15knMWpIiLgeero1dVBVt2qo62PNI6GktGDUkzCwoj5pENTzTFVDUqAZTHDHTN1oxcwFTATBgsrBgEEAYLlHAIBAQQEAwIFIDAKBggqhkjOPQQDAgNIADBFAiEAwaOmji8WpyFGJwV/YrtyjJ4D56G6YtBGUk5FbSwvP3MCIAtfeOURqhgSn28jbZITIn2StOZ+31PoFt+wXZ3IuQ/e',
        key_handle: '1a9tIwwYiYNdmfmxVaksOkxKapK2HtDNSsL4MssbCHILhkMzA0xZYk5IHmBljyblTQ_SnsQea-QEMzgTN2L1Mw',
        public_key: 'BBbTnfbd5sY+rCxZDQi87+akvZedjIqR8567GfrsLR0Gnp4zBpD5zhdSq1wKPvhzEoKJvFuYel1cpdTCzpahrBA='
      },
      assertion: {
        challenge: 'v7G2KR2NYPW6AWxfevjMYflTxbWQqLwEoaZkOnm25K8=',
        id: '1a9tIwwYiYNdmfmxVaksOkxKapK2HtDNSsL4MssbCHILhkMzA0xZYk5IHmBljyblTQ/SnsQea+QEMzgTN2L1Mw==',
        response: {
          client_data_json: 'eyJjaGFsbGVuZ2UiOiJ2N0cyS1IyTllQVzZBV3hmZXZqTVlmbFR4YldRcUx3RW9hWmtPbm0yNUs4Iiwib3JpZ2luIjoiaHR0cHM6Ly9mNjlkZjRkOS5uZ3Jvay5pbyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ==',
          signature: 'MEYCIQCvDq6m7mzBlfhbu+Y20018/iesDoaRyMOwMjVLUgKdJQIhAMFscVb7oUrIhEU/btWUWMj9xjXN9PSUio6ApytJ4Vd7',
          authenticator_data: 'wqc1M3OySstQSIGfoFIjkPhIJrGaCJiQKPeryg70zSsBAAAAbQ=='
        }
      }
    },
    macbook_touch_id: {
      origin: 'http://localhost:3000',
      credential_creation_options: {
        challenge: 'a8mMXGbnWYzB2RG1cTu96rhyXewrZgHR_34BuIuRYTE'
      },
      authenticator_attestation_response: {
        attestation_object: 'o2NmbXRlYXBwbGVnYXR0U3RtdKFjeDVjglkCRzCCAkMwggHJoAMCAQICBgF3z8QYXDAKBggqhkjOPQQDAjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIxMDIyMjE2NDExMVoXDTIxMDIyNTE2NDExMVowgZExSTBHBgNVBAMMQGUwZWM5MjFiOGNkMGYxNGU3ODUzZjUzYThlNDU3NmRkY2U3OWJhN2UwNDkwMjk5OWQ2M2VlOWU2NGIyYmRlZjcxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPBcyVz0vF1QSjcsDdPY7WJrx0jvFh_dZnj56ytGIrdddJz5QcWIqZrEB0csxZFNjPFK0hQooZYvTixgBt7D5kqNVMFMwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCBPAwMwYJKoZIhvdjZAgCBCYwJKEiBCCoFqZ2h1zWBGc8uBsh0z02Ikn7eWVoI8W9OjiRWsQWUjAKBggqhkjOPQQDAgNoADBlAjEA54GIEOvNG3mjCymslbIVwg-tendQ-hRc3PCwcyVVLBdReEnoMiHCAYmh1xCvWV8KAjBkYJa8dnVlNBF92WtuVWL7IrBd5gzGd55roG9U0H7RJm5QC6DPvRdaNl2lnpxdWzZZAjgwggI0MIIBuqADAgECAhBWJVOVx6f7QOviKNgmCFO2MAoGCCqGSM49BAMDMEsxHzAdBgNVBAMMFkFwcGxlIFdlYkF1dGhuIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzODAxWhcNMzAwMzEzMDAwMDAwWjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgy6HLyYUkYECJbn1_Na7Y3i19V8_ywRbxzWZNHX9VJBE35v-GSEXZcaaHdoFCzjUUINAGkNPsk0RLVbD4c-_y5iR_sBpYIG--Wy8d8iN3a9Gpa7h3VFbWvqrk76cCyaRo2YwZDASBgNVHRMBAf8ECDAGAQH_AgEAMB8GA1UdIwQYMBaAFCbXZNnFeMJaZ9Gn3msS0Btj8cbXMB0GA1UdDgQWBBTrroLE_6GsW1HUzyRhBQC-Y713iDAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAN2LGjSBpfrZ27TnZXuEHhRMJ7dbh2pBhsKxR1dQM3In7-VURX72SJUMYy5cSD5wwQIwLIpgRNwgH8_lm8NNKTDBSHhR2WDtanXx60rKvjjNJbiX0MgFvvDH94sHpXHG6A4HaGF1dGhEYXRhWJhJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAAAAAAAAAAAAAAAAAAAAAAAAAAUGNsngcxQiY1p2BB7fCpOWHzbTeilAQIDJiABIVggPBcyVz0vF1QSjcsDdPY7WJrx0jvFh_dZnj56ytGIrdciWCBdJz5QcWIqZrEB0csxZFNjPFK0hQooZYvTixgBt7D5kg',
        client_data_json: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYThtTVhHYm5XWXpCMlJHMWNUdTk2cmh5WGV3clpnSFJfMzRCdUl1UllURSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9'
      }
    }
  }
end
# rubocop:enable Metrics/MethodLength
# rubocop:enable Layout/LineLength
