package org.stagex.root;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;

import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.util.Log;

public class RootService {

	public static final String SERVICE = "RootService";
	public static final IBinder sService = new IRootService.Stub() {

		private void checkCallingPermissions() {
			int uid = getCallingUid();
			Log.v(SERVICE, "Caller UID = " + uid);
		}

		@Override
		public int version() throws RemoteException {
			checkCallingPermissions();
			return 998;
		}

		@Override
		public int exec(String[] cmd, String[] env, String cwd)
				throws RemoteException {
			checkCallingPermissions();
			try {
				File d = null;
				if (cwd != null)
					d = new File(cwd);
				Process p = Runtime.getRuntime().exec(cmd, env, d);
				return p.waitFor();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			return -1;
		}
	};

	public static void main(String[] args) throws Exception {
		Class<?> clzSM = Class.forName("android.os.ServiceManager");
		Method mtdGS = clzSM.getDeclaredMethod("getService", String.class);
		Object service = mtdGS.invoke(null, SERVICE);
		if (service == null) {
			Method mtdAS = clzSM.getDeclaredMethod("addService", String.class,
					IBinder.class);
			mtdAS.invoke(null, SERVICE, sService);
			Log.d(SERVICE, "service added!");
			Looper.prepare();
			Looper.loop();
		} else {
			Log.d(SERVICE, "service already added!");
		}
	}

}
