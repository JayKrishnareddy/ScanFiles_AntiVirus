using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using nClam;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace ScanFiles_AntiVirus.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class FileUploadController : ControllerBase
    {
       // private readonly ILogger<FileUploadController> _logger;
        private readonly IConfiguration _configuration;
        public FileUploadController(
            //ILogger<FileUploadController> logger, 
            IConfiguration configuration)
        {
            //_logger = logger;
            _configuration = configuration;
        }

        [HttpPost]  
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Content("file not selected");

            var ms = new MemoryStream();
            file.OpenReadStream().CopyTo(ms);
            byte[] fileBytes = ms.ToArray();
            string Result = string.Empty;
            try
            {
               // this._logger.LogInformation("ClamAV scan begin for file {0}", file.FileName);
                //var clam = new ClamClient(this._configuration["ClamAVServer:URL"],
                                          //Convert.ToInt32(this._configuration["ClamAVServer:Port"]));
                var clam = new ClamClient(IPAddress.Parse("127.0.0.1"), 3310);
                var scanResult = await clam.SendAndScanFileAsync(fileBytes);
                switch (scanResult.Result)
                {
                    case ClamScanResults.Clean:
                        Result = "Clean";
                 //       this._logger.LogInformation("The file is clean! ScanResult:{1}", scanResult.RawResult);
                        break;
                    case ClamScanResults.VirusDetected:
                        Result = "Virus Detected";
                        //     this._logger.LogError("Virus Found! Virus name: {1}", scanResult.InfectedFiles.FirstOrDefault().VirusName);
                        break;
                    case ClamScanResults.Error:
                        Result = "Error in File";
                        //   this._logger.LogError("An error occured while scaning the file! ScanResult: {1}", scanResult.RawResult);
                        break;
                    case ClamScanResults.Unknown:
                        Result = "Unknown File";
                        // this._logger.LogError("Unknown scan result while scaning the file! ScanResult: {0}", scanResult.RawResult);
                        break;
                }
            }
            catch (Exception ex)
            {
                //this._logger.LogError("ClamAV Scan Exception: {0}", ex.ToString());
            }
            //this._logger.LogInformation("ClamAV scan completed for file {0}", file.FileName);

            return Ok(Result);
        }
    }
}
