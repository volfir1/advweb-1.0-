<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use PhpOffice\PhpSpreadsheet\Spreadsheet;
use PhpOffice\PhpSpreadsheet\Reader\Xlsx;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class SpreadSheetController extends Controller
{
    public function importUsers(Request $request)
    {
        // Validate the uploaded file
        $validator = Validator::make($request->all(), [
            'import_file' => 'required|mimes:xlsx,xls|max:2048',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        try {
            $file = $request->file('import_file');
            $reader = new Xlsx();
            $spreadsheet = $reader->load($file->getPathname());
            $worksheet = $spreadsheet->getActiveSheet();
            $rows = $worksheet->toArray();

            // Remove header row
            array_shift($rows);

            $importedCount = 0;

            foreach ($rows as $row) {
                // Assuming the Excel columns are in this order:
                // first_name, last_name, email, password, is_admin, active_status, contact, address
                $userData = [
                    'first_name' => $row[0],
                    'last_name' => $row[1],
                    'email' => $row[2],
                    'password' => Hash::make($row[3]), // Hash the password
                    'is_admin' => $row[4] == 'Yes' ? 1 : 0,
                    'active_status' => $row[5] == 'Active' ? 1 : 0,
                    'contact' => $row[6],
                    'address' => $row[7],
                ];

                // Validate each user data
                $validator = Validator::make($userData, [
                    'first_name' => 'required|string|max:255',
                    'last_name' => 'required|string|max:255',
                    'email' => 'required|email|unique:users,email',
                    'password' => 'required|string|min:6',
                    'is_admin' => 'boolean',
                    'active_status' => 'boolean',
                    'contact' => 'nullable|string|max:255',
                    'address' => 'nullable|string|max:255',
                ]);

                if ($validator->fails()) {
                    continue; // Skip this row if validation fails
                }

                User::create($userData);
                $importedCount++;
            }

            return response()->json([
                'message' => "$importedCount users imported successfully.",
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'message' => 'An error occurred while importing users.',
                'error' => $e->getMessage()
            ], 500);
        }
    }



    public function exportUsers()
    {
        $users = User::all();

        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();

        // Set up the header row
        $sheet->setCellValue('A1', 'ID');
        $sheet->setCellValue('B1', 'First Name');
        $sheet->setCellValue('C1', 'Last Name');
        $sheet->setCellValue('D1', 'Email');
        $sheet->setCellValue('E1', 'Is Admin');
        $sheet->setCellValue('F1', 'Active Status');
        $sheet->setCellValue('G1', 'Contact');
        $sheet->setCellValue('H1', 'Address');

        // Populate the data
        $row = 2;
        foreach ($users as $user) {
            $sheet->setCellValue('A' . $row, $user->id);
            $sheet->setCellValue('B' . $row, $user->first_name);
            $sheet->setCellValue('C' . $row, $user->last_name);
            $sheet->setCellValue('D' . $row, $user->email);
            $sheet->setCellValue('E' . $row, $user->is_admin ? 'Yes' : 'No');
            $sheet->setCellValue('F' . $row, $user->active_status ? 'Active' : 'Inactive');
            $sheet->setCellValue('G' . $row, $user->contact);
            $sheet->setCellValue('H' . $row, $user->address);
            $row++;
        }

        // Create the Excel file
        $writer = new Xlsx($spreadsheet);
        $filename = 'users_export_' . date('Y-m-d_H-i-s') . '.xlsx';

        // Create a temporary file
        $temp_file = tempnam(sys_get_temp_dir(), 'users_export');
        $writer->save($temp_file);

        // Return the file as a download
        return response()->download($temp_file, $filename, [
            'Content-Type' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        ])->deleteFileAfterSend(true);
    }
}