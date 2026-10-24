-- Run once as the database owner. The API must connect as a SEPARATE role (trustvault_app),
-- not the owner that runs migrations. The app can add and read audit rows but never change them.
REVOKE ALL ON TABLE "AuditEvents" FROM trustvault_app;
GRANT SELECT, INSERT ON TABLE "AuditEvents" TO trustvault_app;
GRANT USAGE, SELECT ON SEQUENCE "AuditEvents_Id_seq" TO trustvault_app;