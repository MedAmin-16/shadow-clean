import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { User, Building, Bell, Shield, Key, Trash2 } from "lucide-react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import type { UserSettings } from "@shared/schema";
import { useToast } from "@/hooks/use-toast";

export default function SettingsPage() {
  const { toast } = useToast();

  const { data: settings } = useQuery<UserSettings>({
    queryKey: ["/api/settings"],
  });

  const [notifications, setNotifications] = useState({
    email: true,
    criticalAlerts: true,
    weeklyReports: false,
    scanComplete: true,
  });

  const [profile, setProfile] = useState({
    name: "John Doe",
    email: "john@company.com",
  });

  const [company, setCompany] = useState({
    name: "Acme Inc.",
    website: "https://acme.com",
  });

  useEffect(() => {
    if (settings) {
      setNotifications(settings.notifications);
      setProfile(settings.profile);
      setCompany(settings.company);
    }
  }, [settings]);

  const updateSettingsMutation = useMutation({
    mutationFn: async (data: Partial<UserSettings>) => {
      const response = await apiRequest("PATCH", "/api/settings", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/settings"] });
      toast({ title: "Settings saved successfully" });
    },
    onError: () => {
      toast({ title: "Failed to save settings", variant: "destructive" });
    },
  });

  const handleSaveProfile = () => {
    updateSettingsMutation.mutate({ profile });
  };

  const handleSaveCompany = () => {
    updateSettingsMutation.mutate({ company });
  };

  const handleNotificationChange = (key: keyof typeof notifications, checked: boolean) => {
    const newNotifications = { ...notifications, [key]: checked };
    setNotifications(newNotifications);
    updateSettingsMutation.mutate({ notifications: newNotifications });
  };

  return (
    <div className="p-6 space-y-6 max-w-4xl" data-testid="page-settings">
      <div>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="text-muted-foreground">Manage your account and preferences</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5 text-primary" />
            Profile
          </CardTitle>
          <CardDescription>Manage your personal information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <Avatar className="h-16 w-16">
              <AvatarFallback className="text-lg">JD</AvatarFallback>
            </Avatar>
            <Button variant="outline" size="sm" data-testid="button-change-avatar">
              Change Avatar
            </Button>
          </div>
          <Separator />
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="name">Full Name</Label>
              <Input
                id="name"
                value={profile.name}
                onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                data-testid="input-profile-name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={profile.email}
                onChange={(e) => setProfile({ ...profile, email: e.target.value })}
                data-testid="input-profile-email"
              />
            </div>
          </div>
          <Button onClick={handleSaveProfile} disabled={updateSettingsMutation.isPending} data-testid="button-save-profile">Save Changes</Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Building className="h-5 w-5 text-primary" />
            Company
          </CardTitle>
          <CardDescription>Manage your company information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="company-name">Company Name</Label>
              <Input
                id="company-name"
                value={company.name}
                onChange={(e) => setCompany({ ...company, name: e.target.value })}
                data-testid="input-company-name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="company-website">Website</Label>
              <Input
                id="company-website"
                type="url"
                value={company.website}
                onChange={(e) => setCompany({ ...company, website: e.target.value })}
                data-testid="input-company-website"
              />
            </div>
          </div>
          <Button onClick={handleSaveCompany} disabled={updateSettingsMutation.isPending} data-testid="button-save-company">Save Changes</Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5 text-primary" />
            Notifications
          </CardTitle>
          <CardDescription>Configure how you receive alerts and updates</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Email Notifications</p>
              <p className="text-sm text-muted-foreground">Receive notifications via email</p>
            </div>
            <Switch
              checked={notifications.email}
              onCheckedChange={(checked) => handleNotificationChange("email", checked)}
              data-testid="switch-email-notifications"
            />
          </div>
          <Separator />
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Critical Alerts</p>
              <p className="text-sm text-muted-foreground">Get notified for critical vulnerabilities</p>
            </div>
            <Switch
              checked={notifications.criticalAlerts}
              onCheckedChange={(checked) => handleNotificationChange("criticalAlerts", checked)}
              data-testid="switch-critical-alerts"
            />
          </div>
          <Separator />
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Weekly Reports</p>
              <p className="text-sm text-muted-foreground">Receive weekly security summary reports</p>
            </div>
            <Switch
              checked={notifications.weeklyReports}
              onCheckedChange={(checked) => handleNotificationChange("weeklyReports", checked)}
              data-testid="switch-weekly-reports"
            />
          </div>
          <Separator />
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Scan Complete</p>
              <p className="text-sm text-muted-foreground">Get notified when scans finish</p>
            </div>
            <Switch
              checked={notifications.scanComplete}
              onCheckedChange={(checked) => handleNotificationChange("scanComplete", checked)}
              data-testid="switch-scan-complete"
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5 text-primary" />
            API Keys
          </CardTitle>
          <CardDescription>Manage API keys for external integrations</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-muted/50 rounded-md">
            <div>
              <p className="font-medium font-mono text-sm">sk-***************abc123</p>
              <p className="text-xs text-muted-foreground mt-1">Created Dec 1, 2024</p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline">Active</Badge>
              <Button variant="ghost" size="sm" data-testid="button-revoke-key">
                Revoke
              </Button>
            </div>
          </div>
          <Button variant="outline" data-testid="button-create-api-key">
            Create New API Key
          </Button>
        </CardContent>
      </Card>

      <Card className="border-destructive/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <Trash2 className="h-5 w-5" />
            Danger Zone
          </CardTitle>
          <CardDescription>Irreversible and destructive actions</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Delete Account</p>
              <p className="text-sm text-muted-foreground">Permanently delete your account and all data</p>
            </div>
            <Button variant="destructive" data-testid="button-delete-account">
              Delete Account
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
