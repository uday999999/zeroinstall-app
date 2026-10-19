package com.security.apkshield.receiver

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.UserManager
import android.widget.Toast

class ShieldDeviceAdminReceiver : DeviceAdminReceiver() {

    companion object {
        fun getComponentName(context: Context): ComponentName =
            ComponentName(context.applicationContext, ShieldDeviceAdminReceiver::class.java)

        fun isAdminActive(context: Context): Boolean {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            return dpm.isAdminActive(getComponentName(context))
        }

        fun isDeviceOrProfileOwner(context: Context): Boolean {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            return dpm.isDeviceOwnerApp(context.packageName) || dpm.isProfileOwnerApp(context.packageName)
        }

        /**
         * If activated as Device Owner / Profile Owner (e.g. via ADB:
         * `adb shell dpm set-device-owner com.security.apkshield/.receiver.ShieldDeviceAdminReceiver`),
         * enforces hardware/OS-level `DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY` which prevents
         * ANY background or foreground APK installation across the entire Android OS.
         */
        fun enforceOsLevelApkBlockIfPossible(context: Context, block: Boolean): Boolean {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            val admin = getComponentName(context)
            if (!isDeviceOrProfileOwner(context)) return false

            return try {
                if (block) {
                    dpm.addUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        dpm.addUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY)
                    }
                } else {
                    dpm.clearUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        dpm.clearUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY)
                    }
                }
                true
            } catch (_: Exception) {
                false
            }
        }
    }

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        enforceOsLevelApkBlockIfPossible(context, true)
        Toast.makeText(
            context,
            "APK Shield Device Admin Enabled: Anti-Tamper Protection Active",
            Toast.LENGTH_LONG
        ).show()
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        return "WARNING: Disabling APK Shield Device Admin will allow malware or unauthorized APK files to install on your phone!"
    }
}
