import { auth } from '@/auth';
import SessionAllLogout from '@/components/auth/session-all-logout';
import SessionOtherLogout from '@/components/auth/session-other-logout';
import { getAuthSessions } from '@/server/auth.server';
import { Badge } from '@repo/shadcn/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@repo/shadcn/card';
import { Laptop, Smartphone, TriangleAlert } from '@repo/shadcn/lucide-react';
import { formatDate } from '@repo/utils';

const SessionsSettings = async () => {
  const sessions = await getAuthSessions();
  const authSession = await auth();
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Active Sessions</CardTitle>
          <CardDescription>
            Manage your active sessions across different devices
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex justify-end">
            <SessionAllLogout />
          </div>

          <div className="space-y-4">
            {sessions
              .sort(
                (a, b) =>
                  new Date(b.updatedAt).getTime() -
                  new Date(a.updatedAt).getTime(),
              )
              .map((session) => (
                <div
                  key={session.id}
                  className="flex items-start justify-between p-4 border rounded-lg"
                >
                  <div className="flex gap-3">
                    {session.device_type === 'desktop' && (
                      <Laptop className="size-7 text-muted-foreground" />
                    )}{' '}
                    {session.device_type === 'mobile' && (
                      <Smartphone className="size-7 text-muted-foreground" />
                    )}
                    {session.device_type === 'unknown' && (
                      <TriangleAlert className="size-7 text-muted-foreground" />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium">
                          {session.device_name} - {session.browser}
                        </h3>
                        {session.id ===
                          authSession?.user?.tokens.session_token && (
                          <Badge variant="secondary">Current Session</Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {session.location} • IP: {session.ip}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {formatDate(
                          session.updatedAt,
                          'MM-DD-YYYY / hh:mm:ss:A',
                        )}
                      </p>
                    </div>
                  </div>

                  {!(
                    session.id === authSession?.user?.tokens?.session_token
                  ) && <SessionOtherLogout session_token={session.id} />}
                </div>
              ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default SessionsSettings;
