package org.stagex.root;

import java.lang.reflect.Method;

import android.content.Context;
import android.os.IBinder;
import android.os.SystemClock;

public class RootSDK {

	static {
		System.loadLibrary("rootsdk");
	}

	private static native int root(String cp);

	public static int root(Context ctx) {
		if (ctx == null)
			return -1;
		StringBuffer cp = new StringBuffer();
		String apk = ctx.getApplicationInfo().sourceDir;
		if (apk != null)
			cp.append(apk);
		return root(cp.toString());
	}

	public static IRootService getRootService() {
		try {
			Class<?> clzSM = Class.forName("android.os.ServiceManager");
			Method mtdGS = clzSM.getDeclaredMethod("getService", String.class);
			IBinder service = (IBinder) mtdGS.invoke(null, RootService.SERVICE);
			if (service != null)
				return IRootService.Stub.asInterface(service);
			return null;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static IRootService getRootService(Context ctx, long timeout) {
		IRootService service;
		service = getRootService();
		if (service != null)
			return service;
		int rc = root(ctx);
		if (rc < 0)
			return null;
		for (int retry = 0; retry < timeout; retry++) {
			service = getRootService();
			if (service != null)
				return service;
			SystemClock.sleep(100);
		}
		return service;
	}

	public static IRootService getRootService(Context ctx) {
		return getRootService(ctx, 15000);
	}
}
